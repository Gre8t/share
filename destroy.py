#!/usr/bin/env python3
"""
AWS Resource Cleanup Tool

This script finds and deletes AWS resources that match a specified search term.
It includes proper error handling, dependency awareness, dry-run capability,
and robust JSON handling.
"""

import subprocess
import json
import argparse
import tempfile
import time
import os
import logging
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define custom exceptions for retry logic
class RetryableException(Exception):
    """Base exception for errors that can be retried."""
    pass

class NonRetryableException(Exception):
    """Base exception for errors that should not be retried."""
    pass

class AWSCommandError(RetryableException):
    """Error executing AWS command that can be retried."""
    pass

class AWSResourceDependencyError(RetryableException):
    """Error due to resource dependencies that can be retried after dependencies are removed."""
    pass

class AWSPermissionError(NonRetryableException):
    """Error due to insufficient permissions."""
    pass

def retry_operation(func, *args, max_attempts=3, backoff_factor=2, **kwargs):
    """Retry an operation with exponential backoff."""
    attempt = 0
    last_exception = None
    
    while attempt < max_attempts:
        try:
            return func(*args, **kwargs)
        except RetryableException as e:
            attempt += 1
            last_exception = e
            if attempt < max_attempts:
                sleep_time = backoff_factor ** attempt
                logger.warning(f"Operation failed, retrying in {sleep_time} seconds... ({attempt}/{max_attempts})")
                time.sleep(sleep_time)
            else:
                logger.error(f"Operation failed after {max_attempts} attempts")
        except NonRetryableException as e:
            logger.error(f"Non-retryable error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise
    
    if last_exception:
        raise last_exception
    
    return None

def run_aws_command(command, check=True, capture_output=True, handle_json=True):
    """Runs an AWS CLI command and returns output."""
    try:
        logger.debug(f"Running command: {command}")
        result = subprocess.run(command, shell=True, check=check, capture_output=capture_output, text=True)
        
        if result.returncode != 0:
            error_msg = f"Command failed with exit code {result.returncode}: {result.stderr}"
            logger.warning(error_msg)
            if "AccessDenied" in result.stderr or "UnauthorizedOperation" in result.stderr:
                raise AWSPermissionError(error_msg)
            elif "DependencyViolation" in result.stderr or "ResourceInUse" in result.stderr:
                raise AWSResourceDependencyError(error_msg)
            else:
                raise AWSCommandError(error_msg)
        
        if capture_output and handle_json and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON output")
                return result.stdout
        elif capture_output:
            return result.stdout
        return None
    except subprocess.CalledProcessError as e:
        error_msg = f"Command execution failed: {e.stderr}"
        logger.error(error_msg)
        
        if "AccessDenied" in e.stderr or "UnauthorizedOperation" in e.stderr:
            raise AWSPermissionError(error_msg)
        elif "DependencyViolation" in e.stderr or "ResourceInUse" in e.stderr:
            raise AWSResourceDependencyError(error_msg)
        else:
            raise AWSCommandError(error_msg)

def write_json_to_temp_file(data):
    """Writes JSON data to a temporary file and returns the file path."""
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
        json.dump(data, tmp)
        return tmp.name

def run_kubectl_command(command, check=True, capture_output=True, handle_json=True):
    """Runs a kubectl command and returns output."""
    try:
        logger.debug(f"Running kubectl command: {command}")
        result = subprocess.run(command, shell=True, check=check, capture_output=capture_output, text=True)
        
        if result.returncode != 0:
            error_msg = f"kubectl command failed with exit code {result.returncode}: {result.stderr}"
            logger.warning(error_msg)
            raise RetryableException(error_msg)
        
        if capture_output and handle_json and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON output from kubectl")
                return result.stdout
        elif capture_output:
            return result.stdout
        return None
    except subprocess.CalledProcessError as e:
        error_msg = f"kubectl command execution failed: {e.stderr}"
        logger.error(error_msg)
        raise RetryableException(error_msg)

def delete_dns_cname(search_term, dry_run=False):
    """Deletes CNAME records containing the search term in Route 53."""
    try:
        logger.info("Searching for CNAME records matching the search term")
        zones = retry_operation(run_aws_command, "aws route53 list-hosted-zones")
        
        if not zones or "HostedZones" not in zones or not zones["HostedZones"]:
            logger.warning("No hosted zones found")
            return
        
        for zone in zones["HostedZones"]:
            zone_id = zone["Id"].split("/")[-1]
            logger.info(f"Checking hosted zone: {zone['Name']} ({zone_id})")
            
            records = retry_operation(
                run_aws_command, 
                f"aws route53 list-resource-record-sets --hosted-zone-id {zone_id}"
            )
            
            if not records or "ResourceRecordSets" not in records or not records["ResourceRecordSets"]:
                logger.warning(f"No records found in zone {zone_id}")
                continue
            
            for record in records["ResourceRecordSets"]:
                if record["Type"] == "CNAME" and search_term in record["Name"]:
                    logger.info(f"Found CNAME record matching '{search_term}': {record['Name']}")
                    
                    if dry_run:
                        logger.info(f"[DRY RUN] Would delete CNAME record: {record['Name']}")
                    else:
                        # Create change batch JSON
                        change_batch = {
                            "Changes": [{
                                "Action": "DELETE",
                                "ResourceRecordSet": record
                            }]
                        }
                        
                        # Use a temporary file for the JSON payload
                        tmp_file = write_json_to_temp_file(change_batch)
                        
                        try:
                            logger.info(f"Deleting CNAME record: {record['Name']}")
                            cmd = f"aws route53 change-resource-record-sets --hosted-zone-id {zone_id} --change-batch file://{tmp_file}"
                            retry_operation(run_aws_command, cmd)
                            logger.info(f"Successfully deleted CNAME record: {record['Name']}")
                        finally:
                            # Clean up temporary file
                            os.remove(tmp_file)
    
    except Exception as e:
        logger.error(f"Error deleting DNS CNAME records: {e}")

def get_load_balancer_dependencies(lb_arn):
    """Gets all dependencies for a load balancer."""
    dependencies = {
        "target_groups": [],
        "listeners": [],
        "rules": []
    }
    
    # Get listeners
    try:
        listeners = retry_operation(
            run_aws_command,
            f"aws elbv2 describe-listeners --load-balancer-arn {lb_arn}"
        )
        
        if listeners and "Listeners" in listeners:
            for listener in listeners["Listeners"]:
                dependencies["listeners"].append(listener["ListenerArn"])
                
                # Get rules for each listener
                try:
                    rules = retry_operation(
                        run_aws_command,
                        f"aws elbv2 describe-rules --listener-arn {listener['ListenerArn']}"
                    )
                    
                    if rules and "Rules" in rules:
                        for rule in rules["Rules"]:
                            if rule["IsDefault"] == False:  # Skip default rules as they're deleted with the listener
                                dependencies["rules"].append(rule["RuleArn"])
                except Exception as e:
                    logger.warning(f"Failed to get rules for listener {listener['ListenerArn']}: {e}")
    except Exception as e:
        logger.warning(f"Failed to get listeners for load balancer {lb_arn}: {e}")
    
    # Get target groups
    try:
        target_groups = retry_operation(
            run_aws_command,
            f"aws elbv2 describe-target-groups --load-balancer-arn {lb_arn}"
        )
        
        if target_groups and "TargetGroups" in target_groups:
            for tg in target_groups["TargetGroups"]:
                dependencies["target_groups"].append(tg["TargetGroupArn"])
    except Exception as e:
        logger.warning(f"Failed to get target groups for load balancer {lb_arn}: {e}")
    
    return dependencies

def delete_load_balancers(search_term, dry_run=False):
    """Deletes ALB and NLB load balancers containing the search term."""
    try:
        logger.info("Searching for load balancers matching the search term")
        lbs = retry_operation(run_aws_command, "aws elbv2 describe-load-balancers")
        
        if not lbs or "LoadBalancers" not in lbs or not lbs["LoadBalancers"]:
            logger.warning("No load balancers found")
            return
        
        for lb in lbs["LoadBalancers"]:
            if search_term in lb["LoadBalancerName"]:
                lb_arn = lb["LoadBalancerArn"]
                logger.info(f"Found load balancer matching '{search_term}': {lb['LoadBalancerName']}")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete load balancer: {lb['LoadBalancerName']}")
                    
                    # Get dependencies to show what else would be deleted
                    dependencies = get_load_balancer_dependencies(lb_arn)
                    
                    if dependencies["listeners"]:
                        logger.info(f"[DRY RUN] Would delete {len(dependencies['listeners'])} listeners")
                    
                    if dependencies["rules"]:
                        logger.info(f"[DRY RUN] Would delete {len(dependencies['rules'])} listener rules")
                    
                    if dependencies["target_groups"]:
                        logger.info(f"[DRY RUN] Would delete {len(dependencies['target_groups'])} target groups")
                else:
                    # Get dependencies
                    dependencies = get_load_balancer_dependencies(lb_arn)
                    
                    # Delete listener rules first
                    for rule_arn in dependencies["rules"]:
                        try:
                            logger.info(f"Deleting listener rule: {rule_arn}")
                            retry_operation(
                                run_aws_command,
                                f"aws elbv2 delete-rule --rule-arn {rule_arn}"
                            )
                        except Exception as e:
                            logger.warning(f"Failed to delete listener rule {rule_arn}: {e}")
                    
                    # Then delete listeners
                    for listener_arn in dependencies["listeners"]:
                        try:
                            logger.info(f"Deleting listener: {listener_arn}")
                            retry_operation(
                                run_aws_command,
                                f"aws elbv2 delete-listener --listener-arn {listener_arn}"
                            )
                        except Exception as e:
                            logger.warning(f"Failed to delete listener {listener_arn}: {e}")
                    
                    # Delete the load balancer
                    logger.info(f"Deleting load balancer: {lb['LoadBalancerName']}")
                    retry_operation(
                        run_aws_command,
                        f"aws elbv2 delete-load-balancer --load-balancer-arn {lb_arn}"
                    )
                    logger.info(f"Successfully deleted load balancer: {lb['LoadBalancerName']}")
                    
                    # Wait for the load balancer to be fully deleted before attempting to delete target groups
                    wait_counter = 0
                    max_wait = 30  # Maximum number of checks
                    while wait_counter < max_wait:
                        try:
                            lb_status = run_aws_command(
                                f"aws elbv2 describe-load-balancers --load-balancer-arns {lb_arn}",
                                check=False
                            )
                            if not lb_status or "LoadBalancers" not in lb_status or not lb_status["LoadBalancers"]:
                                logger.info(f"Load balancer {lb['LoadBalancerName']} has been fully deleted")
                                break
                            logger.info(f"Waiting for load balancer {lb['LoadBalancerName']} to be fully deleted...")
                            time.sleep(10)
                            wait_counter += 1
                        except Exception:
                            # If we get an error, it might be because the load balancer is already gone
                            logger.info(f"Load balancer {lb['LoadBalancerName']} appears to be deleted")
                            break
                    
                    # Now delete target groups
                    for tg_arn in dependencies["target_groups"]:
                        try:
                            logger.info(f"Deleting target group: {tg_arn}")
                            retry_operation(
                                run_aws_command,
                                f"aws elbv2 delete-target-group --target-group-arn {tg_arn}"
                            )
                            logger.info(f"Successfully deleted target group: {tg_arn}")
                        except Exception as e:
                            logger.warning(f"Failed to delete target group {tg_arn}: {e}")
    except Exception as e:
        logger.error(f"Error deleting load balancers: {e}")

def delete_target_groups(search_term, dry_run=False):
    """Deletes any remaining target groups containing the search term."""
    try:
        logger.info("Searching for target groups matching the search term")
        tgs = retry_operation(run_aws_command, "aws elbv2 describe-target-groups")
        
        if not tgs or "TargetGroups" not in tgs or not tgs["TargetGroups"]:
            logger.warning("No target groups found")
            return
        
        for tg in tgs["TargetGroups"]:
            if search_term in tg["TargetGroupName"]:
                tg_arn = tg["TargetGroupArn"]
                logger.info(f"Found target group matching '{search_term}': {tg['TargetGroupName']}")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete target group: {tg['TargetGroupName']}")
                else:
                    try:
                        logger.info(f"Deleting target group: {tg['TargetGroupName']}")
                        retry_operation(
                            run_aws_command,
                            f"aws elbv2 delete-target-group --target-group-arn {tg_arn}"
                        )
                        logger.info(f"Successfully deleted target group: {tg['TargetGroupName']}")
                    except AWSResourceDependencyError as e:
                        logger.warning(f"Target group {tg['TargetGroupName']} is still in use: {e}")
                    except Exception as e:
                        logger.warning(f"Failed to delete target group {tg['TargetGroupName']}: {e}")
    except Exception as e:
        logger.error(f"Error deleting target groups: {e}")

def delete_k8s_namespace(search_term, dry_run=False):
    """Deletes a Kubernetes namespace and removes finalizers if necessary."""
    try:
        logger.info("Checking for Kubernetes connectivity")
        # First check if kubectl is available and configured
        try:
            k8s_version = run_kubectl_command("kubectl version --client -o json", check=False)
            if not k8s_version:
                logger.warning("kubectl command failed or not available, skipping Kubernetes cleanup")
                return
        except Exception:
            logger.warning("kubectl command failed or not available, skipping Kubernetes cleanup")
            return
        
        logger.info("Searching for Kubernetes namespaces matching the search term")
        namespaces = run_kubectl_command("kubectl get namespaces -o json")
        
        if not namespaces or "items" not in namespaces or not namespaces["items"]:
            logger.warning("No Kubernetes namespaces found")
            return
        
        for ns in namespaces["items"]:
            ns_name = ns["metadata"]["name"]
            if search_term in ns_name:
                logger.info(f"Found Kubernetes namespace matching '{search_term}': {ns_name}")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete Kubernetes namespace: {ns_name}")
                else:
                    # Check if namespace is stuck in Terminating state
                    if ns["status"].get("phase") == "Terminating":
                        logger.info(f"Namespace {ns_name} is stuck in Terminating state, removing finalizers")
                        
                        # Remove finalizers
                        if "finalizers" in ns["metadata"] and ns["metadata"]["finalizers"]:
                            patch_json = {"metadata": {"finalizers": None}}
                            tmp_file = write_json_to_temp_file(patch_json)
                            
                            try:
                                logger.info(f"Removing finalizers from namespace: {ns_name}")
                                cmd = f"kubectl patch namespace {ns_name} --patch-file {tmp_file} --type=merge"
                                run_kubectl_command(cmd)
                                logger.info(f"Successfully removed finalizers from namespace: {ns_name}")
                            finally:
                                os.remove(tmp_file)
                    else:
                        # Delete resources in the namespace that might have finalizers
                        logger.info(f"Checking for resources with finalizers in namespace: {ns_name}")
                        
                        resource_types = [
                            "deployment", "statefulset", "service", "pod", 
                            "job", "cronjob", "ingress", "configmap", "secret"
                        ]
                        
                        for resource_type in resource_types:
                            try:
                                resources = run_kubectl_command(
                                    f"kubectl get {resource_type} -n {ns_name} -o json",
                                    check=False
                                )
                                
                                if resources and "items" in resources and resources["items"]:
                                    for resource in resources["items"]:
                                        resource_name = resource["metadata"]["name"]
                                        logger.info(f"Deleting {resource_type} {resource_name} in namespace {ns_name}")
                                        run_kubectl_command(
                                            f"kubectl delete {resource_type} {resource_name} -n {ns_name} --force --grace-period=0",
                                            check=False
                                        )
                            except Exception as e:
                                logger.warning(f"Error cleaning up {resource_type} in namespace {ns_name}: {e}")
                    
                    # Delete the namespace
                    logger.info(f"Deleting Kubernetes namespace: {ns_name}")
                    run_kubectl_command(f"kubectl delete namespace {ns_name} --force --grace-period=0", check=False)
                    logger.info(f"Deletion initiated for Kubernetes namespace: {ns_name}")
    except Exception as e:
        logger.error(f"Error deleting Kubernetes namespaces: {e}")

def delete_ecr_repos(search_term, dry_run=False):
    """Deletes ECR repositories containing the search term."""
    try:
        logger.info("Searching for ECR repositories matching the search term")
        repos = retry_operation(run_aws_command, "aws ecr describe-repositories")
        
        if not repos or "repositories" not in repos or not repos["repositories"]:
            logger.warning("No ECR repositories found")
            return
        
        for repo in repos["repositories"]:
            if search_term in repo["repositoryName"]:
                logger.info(f"Found ECR repository matching '{search_term}': {repo['repositoryName']}")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete ECR repository: {repo['repositoryName']}")
                else:
                    try:
                        logger.info(f"Deleting ECR repository: {repo['repositoryName']}")
                        retry_operation(
                            run_aws_command,
                            f"aws ecr delete-repository --repository-name {repo['repositoryName']} --force"
                        )
                        logger.info(f"Successfully deleted ECR repository: {repo['repositoryName']}")
                    except Exception as e:
                        logger.warning(f"Failed to delete ECR repository {repo['repositoryName']}: {e}")
    except Exception as e:
        logger.error(f"Error deleting ECR repositories: {e}")

def delete_security_groups(search_term, dry_run=False):
    """Deletes security groups that match the search term."""
    try:
        logger.info("Searching for security groups matching the search term")
        security_groups = retry_operation(
            run_aws_command,
            "aws ec2 describe-security-groups"
        )
        
        if not security_groups or "SecurityGroups" not in security_groups or not security_groups["SecurityGroups"]:
            logger.warning("No security groups found")
            return
        
        # First, find security groups with dependencies
        sg_dependencies = {}
        for sg in security_groups["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_dependencies[sg_id] = []
            
            # Check if it references other security groups
            for ip_perm in sg.get("IpPermissions", []):
                for user_id_group_pair in ip_perm.get("UserIdGroupPairs", []):
                    if "GroupId" in user_id_group_pair:
                        sg_dependencies[sg_id].append(user_id_group_pair["GroupId"])
        
        # Identify security groups matching search term
        matching_sg_ids = []
        for sg in security_groups["SecurityGroups"]:
            if search_term in sg["GroupName"] or (sg.get("Tags") and any(search_term in tag.get("Value", "") for tag in sg.get("Tags", []))):
                matching_sg_ids.append(sg["GroupId"])
                logger.info(f"Found security group matching '{search_term}': {sg['GroupName']} ({sg['GroupId']})")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete security group: {sg['GroupName']} ({sg['GroupId']})")
        
        # If not dry run, proceed with deletion
        if not dry_run and matching_sg_ids:
            # Try to delete security groups multiple times since dependencies might be complex
            # First, try to delete self-referenced security groups
            for attempt in range(3):
                logger.info(f"Security group deletion attempt {attempt+1}")
                successfully_deleted = []
                
                for sg_id in matching_sg_ids:
                    # Skip already deleted SGs
                    if sg_id in successfully_deleted:
                        continue
                    
                    # Try to delete the security group
                    try:
                        logger.info(f"Attempting to delete security group: {sg_id}")
                        retry_operation(
                            run_aws_command,
                            f"aws ec2 delete-security-group --group-id {sg_id}"
                        )
                        logger.info(f"Successfully deleted security group: {sg_id}")
                        successfully_deleted.append(sg_id)
                    except AWSResourceDependencyError:
                        logger.warning(f"Security group {sg_id} still has dependencies, will retry later")
                    except Exception as e:
                        logger.warning(f"Failed to delete security group {sg_id}: {e}")
                
                # If we've deleted all security groups, we're done
                if len(successfully_deleted) == len(matching_sg_ids):
                    logger.info("Successfully deleted all matching security groups")
                    break
                
                # Wait before retrying
                if attempt < 2:
                    time.sleep(10)
    except Exception as e:
        logger.error(f"Error deleting security groups: {e}")

def identify_stack_dependencies(stacks):
    """Identifies dependencies between CloudFormation stacks."""
    # Build dependency graph
    dependency_graph = {}
    
    for stack in stacks:
        stack_name = stack["StackName"]
        dependency_graph[stack_name] = {
            "dependents": [],
            "dependencies": []
        }
    
    # Identify dependencies based on outputs and parameters
    for stack in stacks:
        stack_name = stack["StackName"]
        
        # Check for outputs that might be used by other stacks
        if "Outputs" in stack:
            for output in stack["Outputs"]:
                output_name = output["OutputKey"]
                
                # Check if this output is used as a parameter in other stacks
                for other_stack in stacks:
                    if other_stack["StackName"] == stack_name:
                        continue
                    
                    if "Parameters" in other_stack:
                        for param in other_stack["Parameters"]:
                            if param["ParameterValue"] == output["OutputValue"]:
                                # This stack is a dependency for other_stack
                                dependency_graph[stack_name]["dependents"].append(other_stack["StackName"])
                                dependency_graph[other_stack["StackName"]]["dependencies"].append(stack_name)
    
    return dependency_graph

def delete_cloudformation_stacks(search_term, dry_run=False):
    """Deletes CloudFormation stacks containing the search term, respecting dependencies."""
    try:
        logger.info("Searching for CloudFormation stacks matching the search term")
        stacks = retry_operation(
            run_aws_command,
            "aws cloudformation describe-stacks"
        )
        
        if not stacks or "Stacks" not in stacks or not stacks["Stacks"]:
            logger.warning("No CloudFormation stacks found")
            return
        
        # Identify stacks matching search term
        matching_stacks = []
        for stack in stacks["Stacks"]:
            stack_name = stack["StackName"]
            
            # Check if stack name or any tag matches search term
            if search_term in stack_name or (stack.get("Tags") and any(search_term in tag.get("Value", "") for tag in stack.get("Tags", []))):
                matching_stacks.append(stack)
                logger.info(f"Found CloudFormation stack matching '{search_term}': {stack_name}")
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete CloudFormation stack: {stack_name}")
        
        if not matching_stacks:
            logger.info("No matching CloudFormation stacks found")
            return
        
        if not dry_run:
            # Build dependency graph among matching stacks
            dependency_graph = identify_stack_dependencies(matching_stacks)
            
            # Find stacks with no dependents (leaf nodes)
            deletion_order = []
            remaining_stacks = set(stack["StackName"] for stack in matching_stacks)
            
            # Keep finding leaf nodes until all stacks are processed
            while remaining_stacks:
                leaf_nodes = []
                
                for stack_name in remaining_stacks:
                    # Only consider stacks with no dependents or whose dependents have already been processed
                    if not any(dependent in remaining_stacks for dependent in dependency_graph[stack_name]["dependents"]):
                        leaf_nodes.append(stack_name)
                
                if not leaf_nodes:
                    # If no leaf nodes found but we still have stacks, there's a circular dependency
                    logger.warning("Circular dependency detected in CloudFormation stacks")
                    # Just delete remaining stacks in any order
                    deletion_order.extend(list(remaining_stacks))
                    break
                
                # Add leaf nodes to deletion order
                deletion_order.extend(leaf_nodes)
                # Remove processed stacks
                remaining_stacks -= set(leaf_nodes)
            
            # Delete stacks in order
            for stack_name in deletion_order:
                try:
                    logger.info(f"Deleting CloudFormation stack: {stack_name}")
                    retry_operation(
                        run_aws_command,
                        f"aws cloudformation delete-stack --stack-name {stack_name}"
                    )
                    logger.info(f"Deletion initiated for CloudFormation stack: {stack_name}")
                    
                    # Wait for stack to be deleted
                    logger.info(f"Waiting for stack {stack_name} to be deleted...")
                    retry_operation(
                        run_aws_command,
                        f"aws cloudformation wait stack-delete-complete --stack-name {stack_name}"
                    )
                    logger.info(f"Successfully deleted CloudFormation stack: {stack_name}")
                except Exception as e:
                    logger.warning(f"Failed to delete CloudFormation stack {stack_name}: {e}")
    except Exception as e:
        logger.error(f"Error deleting CloudFormation stacks: {e}")

def main():
    parser = argparse.ArgumentParser(description="Delete AWS resources based on a search term.")
    parser.add_argument("--search", required=True, help="Search term to match resources.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without actually deleting anything.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level")
    args = parser.parse_args()

    # Set logging level
    logger.setLevel(getattr(logging, args.log_level))

    search_term = args.search
    dry_run = args.dry_run

    if dry_run:
        logger.info(f"DRY RUN MODE: Resources will not be deleted")
    
    logger.info(f"Searching for resources matching: {search_term}")
    
    # Delete resources in dependency order
    # 1. First client-facing resources
    delete_dns_cname(search_term, dry_run)
    
    # 2. Then stateless resources
    delete_load_balancers(search_term, dry_run)
    delete_target_groups(search_term, dry_run)
    
    # 3. Then container resources
    delete_k8s_namespace(search_term, dry_run)
    delete_ecr_repos(search_term, dry_run)
    
    # 4. Then security groups
    delete_security_groups(search_term, dry_run)
    
    # 5. Finally CloudFormation stacks which may have complex dependencies
    delete_cloudformation_stacks(search_term, dry_run)
    
    logger.info("Resource deletion process completed")

if __name__ == "__main__":
    main()
