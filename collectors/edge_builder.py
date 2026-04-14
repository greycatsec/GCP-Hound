#!/usr/bin/env python3
from utils.id_utils import normalize_dataset_id

def safe_add_edge(edges, start_id, end_id, kind, properties):
    """
    Safely add an edge to edges list with validation of node IDs.
    Prevents "Node ID cannot be empty" errors by validating before creation.
    """
    if not start_id or not str(start_id).strip():
        return False
    if not end_id or not str(end_id).strip():
        return False

    edge = {
        "start": {"value": str(start_id).strip()},
        "end": {"value": str(end_id).strip()},
        "kind": kind,
        "properties": properties or {}
    }
    edges.append(edge)
    return True

def build_edges(projects, iam_data, users, service_accounts, buckets, secrets, bigquery_datasets=None, debug=False):
    """
    Build comprehensive attack path edges from collected GCP data.
    Returns list of edges for BloodHound visualization.
    """
    edges = []
    stats = {"created": 0, "skipped": 0}

    if not projects:
        print("[!] No projects provided to edge builder")
        return edges

    print(f"[*] Edge Builder: Processing {len(projects)} projects, {len(iam_data)} IAM policies")

    if bigquery_datasets:
        print(f"[*] Edge Builder: Including {len(bigquery_datasets)} BigQuery datasets")

    iam_edges = build_iam_binding_edges(iam_data, projects, debug)
    edges.extend(iam_edges)
    stats["created"] += len(iam_edges)

    sa_edges = build_service_account_edges(service_accounts, projects, iam_data, debug)
    edges.extend(sa_edges)
    stats["created"] += len(sa_edges)

    resource_edges = build_resource_ownership_edges(projects, buckets, secrets, service_accounts, bigquery_datasets, debug)
    edges.extend(resource_edges)
    stats["created"] += len(resource_edges)

    privesc_edges = build_privilege_escalation_edges(iam_data, service_accounts, secrets, debug)
    edges.extend(privesc_edges)
    stats["created"] += len(privesc_edges)

    print(f"[+] Edge Builder: Created {len(edges)} attack relationship edges")
    return edges


def build_service_account_permission_edges(service_account_permissions, debug=False):
    """
    Build edges from service account IAM permission analysis.
    Creates User->ServiceAccount relationship edges for impersonation, key creation, etc.
    """
    edges = []
    edges_created = 0
    edges_skipped = 0

    if not service_account_permissions:
        if debug:
            print("[DEBUG] No service account permission data provided")
        return edges

    for sa_perms in service_account_permissions:
        sa_email = sa_perms.get('serviceAccount')
        if not sa_email:
            edges_skipped += 1
            continue

        for binding in sa_perms.get('bindings', []):
            role = binding.get('role', '')
            for member in binding.get('members', []):
                prefix = None
                if member.startswith('user:'):
                    prefix = 'user:'
                elif member.startswith('serviceAccount:'):
                    prefix = 'serviceAccount:'
                else:
                    continue

                source_id = member.replace(prefix, '')
                edge_type, risk_level = determine_sa_permission_edge_type(role)
                if not edge_type:
                    continue

                success = safe_add_edge(
                    edges=edges,
                    start_id=source_id,
                    end_id=sa_email,
                    kind=edge_type,
                    properties={
                        'source': 'service_account_iam_policy',
                        'role': role,
                        'risklevel': risk_level,
                        'project': sa_perms.get('project', 'Unknown'),
                        'description': f"Can {edge_type} service account via {role}"
                    }
                )
                if success:
                    edges_created += 1
                    if debug and edges_created <= 10:
                        print(f"[DEBUG] ✅ SA permission edge: {source_id} --[{edge_type}]-> {sa_email}")
                else:
                    edges_skipped += 1

    print(f"[+] Built {edges_created} service account permission edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid service account permission edges")
    return edges


def determine_sa_permission_edge_type(role):
    """
    Determine GCP_-prefixed edge type and risk level from IAM role for SA permissions.
    Returns (edge_type, risk_level) tuple.
    """
    role_lower = role.lower()

    if 'serviceaccountuser' in role_lower or 'iam.serviceaccounts.actas' in role_lower:
        return 'GCP_CanImpersonate', 'HIGH'

    if 'serviceaccountkeyAdmin' in role_lower or 'iam.serviceaccountkeys.create' in role_lower:
        return 'GCP_CanCreateKeys', 'CRITICAL'

    if 'serviceaccountadmin' in role_lower or 'iam.serviceaccounts.setiampolicy' in role_lower:
        return 'GCP_CanManageSA', 'HIGH'

    if 'serviceaccounttokencreator' in role_lower or 'iam.serviceaccounts.getaccesstoken' in role_lower:
        return 'GCP_CanGetAccessToken', 'HIGH'

    if role_lower == 'roles/owner':
        return 'GCP_CanManageSA', 'CRITICAL'
    elif role_lower == 'roles/editor':
        return 'GCP_CanImpersonate', 'HIGH'

    if 'iam.securityadmin' in role_lower:
        return 'GCP_CanManageSA', 'CRITICAL'

    return None, None


def get_sa_roles_from_iam(sa_email, iam_data):
    """Extract actual roles assigned to service account from IAM data"""
    sa_roles = []
    if not iam_data:
        return sa_roles
    service_account_identifier = f"serviceAccount:{sa_email}"
    for iam_policy in iam_data:
        for binding in iam_policy.get('bindings', []):
            if service_account_identifier in binding.get('members', []):
                sa_roles.append(binding.get('role', ''))
    return sa_roles


def analyze_sa_actual_privileges(sa_email, iam_data):
    """Analyze service account's ACTUAL privilege level from IAM data"""
    if not iam_data:
        return "UNKNOWN"
    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)
    critical_roles = ['roles/owner', 'roles/iam.securityAdmin', 'roles/iam.organizationAdmin']
    high_roles = ['roles/editor', 'roles/compute.admin', 'roles/storage.admin', 'roles/iam.serviceAccountAdmin']
    medium_roles = ['roles/compute.instanceAdmin', 'roles/storage.objectAdmin', 'roles/bigquery.dataEditor']
    if any(role in critical_roles for role in sa_roles):
        return "CRITICAL"
    elif any(role in high_roles for role in sa_roles):
        return "HIGH"
    elif any(role in medium_roles for role in sa_roles):
        return "MEDIUM"
    elif any('viewer' in role.lower() for role in sa_roles):
        return "LOW"
    else:
        return "LIMITED"


def get_privilege_reason(sa_email, iam_data):
    """Get human-readable reason for SA privilege level"""
    roles = get_sa_roles_from_iam(sa_email, iam_data)
    critical_roles = [r for r in roles if r in ['roles/owner', 'roles/iam.securityAdmin']]
    admin_roles = [r for r in roles if 'admin' in r.lower()]
    if critical_roles:
        return f"Has critical roles: {', '.join(critical_roles)}"
    elif admin_roles:
        return f"Has admin roles: {', '.join(admin_roles)}"
    elif len(roles) > 3:
        return f"Has multiple roles ({len(roles)}): {', '.join(roles[:3])}..."
    elif roles:
        return f"Has roles: {', '.join(roles)}"
    else:
        return "No roles found"


def build_service_account_edges(service_accounts, projects, iam_data=None, debug=False):
    """Build service account relationship edges with dynamic privilege analysis"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        project_id = sa.get('project', '').lower()

        if not sa_email or not project_id:
            edges_skipped += 1
            continue

        # Structural containment edge (non-traversable)
        success = safe_add_edge(
            edges=edges,
            start_id=project_id,
            end_id=sa_email,
            kind="GCP_ContainsServiceAccount",
            properties={
                "source": "service_account_ownership",
                "risklevel": "LOW",
                "keycount": sa.get('keyCount', 0),
                "disabled": sa.get('disabled', False),
                "description": f"Project {project_id} contains service account {sa_email}"
            }
        )
        if success:
            edges_created += 1
        else:
            edges_skipped += 1

        # Traversable high-privilege edge (SA → Project)
        actual_privilege_level = analyze_sa_actual_privileges(sa_email, iam_data)
        if actual_privilege_level in ['CRITICAL', 'HIGH']:
            success = safe_add_edge(
                edges=edges,
                start_id=sa_email,
                end_id=project_id,
                kind="GCP_HighPrivilegeServiceAccount",
                properties={
                    "source": "iam_privilege_analysis",
                    "risklevel": actual_privilege_level,
                    "actualroles": get_sa_roles_from_iam(sa_email, iam_data),
                    "privilegereason": get_privilege_reason(sa_email, iam_data),
                    "description": f"Service account {sa_email} has {actual_privilege_level} privileges"
                }
            )
            if success:
                edges_created += 1
            else:
                edges_skipped += 1

    print(f"[+] Built {edges_created} service account edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid service account edges")
    return edges


def determine_enhanced_edge_kind_from_role(role):
    """Map GCP IAM role to GCP_-prefixed edge kind for IAM binding edges"""
    role_lower = role.lower()

    if role_lower == 'roles/owner':
        return 'GCP_OwnsProject'
    if role_lower in ['roles/resourcemanager.projectiamadmin', 'roles/iam.securityadmin', 'roles/iam.organizationadmin']:
        return 'GCP_ManageProjectIAM'
    if role_lower == 'roles/editor':
        return 'GCP_CanEditProject'
    if role_lower in ['roles/viewer', 'roles/browser']:
        return 'GCP_CanViewProject'
    if role_lower.startswith('roles/compute.') and 'admin' in role_lower:
        return 'GCP_ManageProjectCompute'
    if role_lower.startswith('roles/storage.') and 'admin' in role_lower:
        return 'GCP_ManageProjectStorage'
    if role_lower.startswith('roles/bigquery.') and 'admin' in role_lower:
        return 'GCP_ManageProjectBigQuery'
    if role_lower.startswith(('roles/datastore.', 'roles/firebase.', 'roles/firebaseauth.', 'roles/firebasedatabase.')):
        return 'GCP_HasRoleOnProject'
    if 'admin' in role_lower and not any(x in role_lower for x in ['datastore', 'firebase']):
        return 'GCP_AdministerProject'
    return 'GCP_HasRoleOnProject'


def get_attack_surface_for_role(role):
    """Get attack surface description for GCP role"""
    attack_surfaces = {
        'roles/owner': 'Full project control including IAM, billing, and resource management',
        'roles/editor': 'Resource creation/modification without IAM management',
        'roles/viewer': 'Read-only access to project resources',
        'roles/iam.securityAdmin': 'IAM policy management and security configuration',
        'roles/compute.admin': 'Compute Engine instances and infrastructure control',
        'roles/storage.admin': 'Cloud Storage buckets and objects management',
        'roles/bigquery.admin': 'BigQuery datasets, jobs, and data access'
    }
    return attack_surfaces.get(role, 'Specialized role-based access to project resources')


def determine_risk_level_from_role(role):
    """Determine risk level from GCP role"""
    role_lower = role.lower()
    if any(critical in role_lower for critical in ['owner', 'securityadmin', 'iam.admin']):
        return 'CRITICAL'
    elif any(high in role_lower for high in ['editor', 'admin', 'compute.admin', 'storage.admin']):
        return 'HIGH'
    elif any(medium in role_lower for medium in ['dataviewer', 'bigquery.user', 'cloudsql.client']):
        return 'MEDIUM'
    elif 'viewer' in role_lower or 'browser' in role_lower:
        return 'LOW'
    else:
        return 'MEDIUM'


def build_iam_binding_edges(iam_data, projects, debug=False):
    """Build edges from IAM policy bindings using GCP_-prefixed edge kinds"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId', '').lower()
        for binding in iam_policy.get('bindings', []):
            role = binding.get('role', '')
            for member in binding.get('members', []):
                if member.startswith('serviceAccount:'):
                    member_id = member.replace('serviceAccount:', '').lower()
                    member_type = 'ServiceAccount'
                elif member.startswith('user:'):
                    member_id = member.replace('user:', '').lower()
                    member_type = 'User'
                elif member.startswith('group:'):
                    member_id = member.replace('group:', '').lower()
                    member_type = 'Group'
                else:
                    continue

                edge_kind = determine_enhanced_edge_kind_from_role(role)
                risk_level = determine_risk_level_from_role(role)

                success = safe_add_edge(
                    edges=edges,
                    start_id=member_id,
                    end_id=project_id,
                    kind=edge_kind,
                    properties={
                        "source": "iam_policy_binding",
                        "role": role,
                        "risklevel": risk_level,
                        "membertype": member_type,
                        "projectid": project_id,
                        "attacksurface": get_attack_surface_for_role(role),
                        "description": f"{member_type} {member_id} has {role} on project {project_id}"
                    }
                )
                if success:
                    edges_created += 1
                    if debug and edges_created <= 5:
                        print(f"[DEBUG] ✅ IAM edge: {member_id} --[{edge_kind}]-> {project_id}")
                else:
                    edges_skipped += 1

    print(f"[+] Built {edges_created} IAM binding edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid IAM binding edges")
    return edges


def build_resource_ownership_edges(projects, buckets, secrets, service_accounts, bigquery_datasets=None, debug=False):
    """Build resource ownership edges using GCP_-prefixed edge kinds"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()
        project_id = bucket.get('project', '').lower()
        if bucket_name and project_id:
            is_public = bucket.get('publicAccess') == 'allUsers'
            has_versioning = bucket.get('versioning', False)
            risk_level = "CRITICAL" if is_public else ("LOW" if has_versioning else "MEDIUM")
            success = safe_add_edge(
                edges=edges,
                start_id=project_id,
                end_id=bucket_name,
                kind="GCP_OwnsStorageBucket",
                properties={
                    "source": "resource_ownership",
                    "resourcetype": "Storage Bucket",
                    "risklevel": risk_level,
                    "publicaccess": bucket.get('publicAccess', 'unknown'),
                    "versioning": has_versioning,
                    "location": bucket.get('location', ''),
                    "description": f"Project {project_id} owns storage bucket {bucket_name}"
                }
            )
            if success:
                edges_created += 1
            else:
                edges_skipped += 1

    for secret in secrets:
        secret_name = secret.get('name', '').lower()
        project_id = secret.get('project', '').lower()
        if secret_name and project_id:
            success = safe_add_edge(
                edges=edges,
                start_id=project_id,
                end_id=secret_name,
                kind="GCP_OwnsSecret",
                properties={
                    "source": "resource_ownership",
                    "resourcetype": "Secret",
                    "risklevel": "HIGH",
                    "description": f"Project {project_id} owns secret {secret_name}"
                }
            )
            if success:
                edges_created += 1
            else:
                edges_skipped += 1

    if bigquery_datasets:
        for dataset in bigquery_datasets:
            dataset_id = dataset.get('dataset_id', '')
            project_id = dataset.get('project', '').lower()
            if dataset_id and project_id:
                canonical_dataset_id = normalize_dataset_id(dataset_id, project_id)
                success = safe_add_edge(
                    edges=edges,
                    start_id=project_id,
                    end_id=canonical_dataset_id,
                    kind="GCP_OwnsDataset",
                    properties={
                        "source": "resource_ownership",
                        "resourcetype": "BigQuery Dataset",
                        "risklevel": dataset.get('riskLevel', 'MEDIUM'),
                        "tablecount": dataset.get('table_count', 0),
                        "location": dataset.get('location', 'Unknown'),
                        "description": f"Project {project_id} owns BigQuery dataset {canonical_dataset_id}"
                    }
                )
                if success:
                    edges_created += 1
                else:
                    edges_skipped += 1

    print(f"[+] Built {edges_created} resource ownership edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid resource ownership edges")
    return edges


def get_enhanced_permissions_for_role(role):
    """Get permissions contained in a GCP role for privilege escalation analysis"""
    role_permissions = {
        'roles/owner': [
            'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
            'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt',
            'compute.instances.create', 'cloudfunctions.functions.create',
            'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy',
            'secretmanager.secrets.get', 'secretmanager.versions.access'
        ],
        'roles/editor': [
            'iam.serviceAccounts.actAs',
            'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt',
            'compute.instances.create',
            'cloudfunctions.functions.create', 'compute.instances.setServiceAccount'
        ],
        'roles/iam.serviceAccountTokenCreator': [
            'iam.serviceAccounts.getAccessToken',
            'iam.serviceAccounts.signBlob',
            'iam.serviceAccounts.signJwt'
        ],
        'roles/iam.serviceAccountUser': ['iam.serviceAccounts.actAs'],
        'roles/iam.serviceAccountKeyAdmin': ['iam.serviceAccountKeys.create', 'iam.serviceAccountKeys.get'],
        'roles/iam.securityAdmin': ['iam.serviceAccounts.actAs', 'resourcemanager.projects.setIamPolicy'],
        'roles/compute.admin': ['compute.instances.create', 'compute.instances.setServiceAccount'],
        'roles/storage.admin': ['storage.buckets.setIamPolicy'],
        'roles/deploymentmanager.editor': ['deploymentmanager.deployments.create'],
        'roles/secretmanager.secretAccessor': ['secretmanager.versions.access'],
        'roles/secretmanager.admin': ['secretmanager.secrets.get', 'secretmanager.versions.access']
    }
    return role_permissions.get(role, [])


def get_escalation_risk_level(permission):
    critical_perms = [
        'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
        'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy',
        'secretmanager.versions.access'
    ]
    high_perms = [
        'compute.instances.create', 'cloudfunctions.functions.create',
        'compute.instances.setServiceAccount', 'cloudfunctions.functions.sourceCodeSet',
        'secretmanager.secrets.get'
    ]
    if permission in critical_perms:
        return 'CRITICAL'
    elif permission in high_perms:
        return 'HIGH'
    else:
        return 'MEDIUM'


def get_attack_vector_for_permission(permission):
    """Map GCP permissions to attack vectors"""
    attack_vectors = {
        'iam.serviceAccounts.actAs': 'Service Account Impersonation',
        'iam.serviceAccounts.getAccessToken': 'Token Minting',
        'iam.serviceAccounts.signBlob': 'Credential Forging',
        'iam.serviceAccounts.signJwt': 'Credential Forging',
        'iam.serviceAccounts.setIamPolicy': 'Service Account Policy Takeover',
        'iam.serviceAccountKeys.create': 'Service Account Key Creation',
        'compute.instances.create': 'Compute Instance Privilege Escalation',
        'compute.instances.setServiceAccount': 'Instance Service Account Hijacking',
        'cloudfunctions.functions.create': 'Serverless Code Execution',
        'resourcemanager.projects.setIamPolicy': 'Project Policy Takeover',
        'storage.buckets.setIamPolicy': 'Bucket Policy Manipulation',
        'secretmanager.versions.access': 'Secret Value Access',
        'secretmanager.secrets.get': 'Secret Metadata Access'
    }
    return attack_vectors.get(permission, 'Resource Manipulation')


def get_mitre_technique_for_permission(permission):
    """Map GCP permissions to MITRE ATT&CK techniques"""
    mitre_mapping = {
        'iam.serviceAccounts.actAs': 'T1078.004',
        'iam.serviceAccounts.getAccessToken': 'T1078.004',
        'iam.serviceAccountKeys.create': 'T1098.001',
        'compute.instances.create': 'T1578.002',
        'cloudfunctions.functions.create': 'T1578.001'
    }
    return mitre_mapping.get(permission, '')


def clean_member_id(member):
    if member.startswith('serviceAccount:'):
        return member.replace('serviceAccount:', '').lower()
    elif member.startswith('user:'):
        return member.replace('user:', '').lower()
    elif member.startswith('group:'):
        return member.replace('group:', '').lower()
    return None


def build_privilege_escalation_edges(iam_data, service_accounts, secrets=None, debug=False):
    """
    Build privilege escalation edges using GCP_-prefixed edge kinds.

    Traversable edges (source fully controls destination):
      - GCP_CanImpersonate, GCP_CanCreateKeys, GCP_CanGetAccessToken,
        GCP_CanModifyIamPolicy, GCP_CanModifyProjectPolicy, GCP_CanReadSecrets

    Non-traversable edges (partial capability / wrong destination node):
      - GCP_CanSignBlob, GCP_CanSignJWT (supporting edges — partial SA capability)
      - GCP_CanCreateComputeInstance, GCP_CanCreateCloudFunction,
        GCP_CanChangeInstanceServiceAccount (destination is project, not the SA)
      - GCP_CanModifyBucketPoliciesInProject, GCP_CanReadSecretsInProject (project-wide)
    """
    edges = []
    edges_created = 0
    edges_skipped = 0

    sa_by_project = {}
    for sa in service_accounts:
        project_id = sa.get('project', '').lower()
        sa_email = sa.get('email', '').lower()
        if project_id and sa_email:
            sa_by_project.setdefault(project_id, []).append(sa_email)

    # SA-scoped permissions → edges to the target SA
    # Traversable: actAs, createKeys, getAccessToken, setIamPolicy
    # Non-traversable: signBlob, signJwt (partial capability — supporting edges only)
    sa_scoped_permissions = {
        'iam.serviceAccounts.actAs':          'GCP_CanImpersonate',        # traversable
        'iam.serviceAccounts.getAccessToken': 'GCP_CanGetAccessToken',     # traversable
        'iam.serviceAccounts.setIamPolicy':   'GCP_CanModifyIamPolicy',    # traversable
        'iam.serviceAccountKeys.create':      'GCP_CanCreateKeys',         # traversable
        'iam.serviceAccounts.signBlob':        'GCP_CanSignBlob',           # non-traversable
        'iam.serviceAccounts.signJwt':         'GCP_CanSignJWT',            # non-traversable
    }

    # Secret-scoped permissions → edges to the secret
    # Traversable: versions.access (reads the actual secret value)
    # Non-traversable: secrets.get (metadata only)
    secret_scoped_permissions = {
        'secretmanager.versions.access': 'GCP_CanReadSecrets',         # traversable
        'secretmanager.secrets.get':     'GCP_CanReadSecretMetadata'   # non-traversable
    }

    # Project-scoped permissions → edges to the project
    # All non-traversable: destination is the project, actual escalation target is the SA
    project_scoped_permissions = {
        'compute.instances.create':                 'GCP_CanCreateComputeInstance',
        'compute.instances.setServiceAccount':       'GCP_CanChangeInstanceServiceAccount',
        'cloudfunctions.functions.create':           'GCP_CanCreateCloudFunction',
        'resourcemanager.projects.setIamPolicy':     'GCP_CanModifyProjectPolicy',  # traversable
        'storage.buckets.setIamPolicy':              'GCP_CanModifyBucketPoliciesInProject',
        'secretmanager.versions.access':             'GCP_CanReadSecretsInProject'
    }

    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId', '').lower()
        for binding in iam_policy.get('bindings', []):
            role = binding.get('role', '')
            escalation_perms = get_enhanced_permissions_for_role(role)

            for member in binding.get('members', []):
                member_id = clean_member_id(member)
                if not member_id:
                    continue

                for perm in escalation_perms:

                    if perm in sa_scoped_permissions:
                        edge_kind = sa_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        for target_sa in sa_by_project.get(project_id, []):
                            if target_sa == member_id:
                                continue
                            success = safe_add_edge(
                                edges=edges,
                                start_id=member_id,
                                end_id=target_sa,
                                kind=edge_kind,
                                properties={
                                    "source": "privilege_escalation_analysis",
                                    "permission": perm,
                                    "role": role,
                                    "risklevel": risk_level,
                                    "projectcontext": project_id,
                                    "mitretechnique": get_mitre_technique_for_permission(perm),
                                    "attackvector": get_attack_vector_for_permission(perm),
                                    "description": f"{member_id} can {perm} on service account {target_sa}"
                                }
                            )
                            if success:
                                edges_created += 1
                                if debug and edges_created <= 10:
                                    print(f"[DEBUG] ✅ SA-to-SA edge: {member_id} --[{edge_kind}]-> {target_sa}")
                            else:
                                edges_skipped += 1

                    elif perm in project_scoped_permissions:
                        edge_kind = project_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        success = safe_add_edge(
                            edges=edges,
                            start_id=member_id,
                            end_id=project_id,
                            kind=edge_kind,
                            properties={
                                "source": "privilege_escalation_analysis",
                                "permission": perm,
                                "role": role,
                                "risklevel": risk_level,
                                "mitretechnique": get_mitre_technique_for_permission(perm),
                                "attackvector": get_attack_vector_for_permission(perm),
                                "description": f"{member_id} can escalate via {perm} in {project_id}"
                            }
                        )
                        if success:
                            edges_created += 1
                        else:
                            edges_skipped += 1

                    elif perm in secret_scoped_permissions:
                        edge_kind = secret_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        project_secrets = [s for s in (secrets or []) if s.get('project', '').lower() == project_id]
                        for secret in project_secrets:
                            secret_name = secret.get('name', '').lower()
                            if not secret_name:
                                continue
                            success = safe_add_edge(
                                edges=edges,
                                start_id=member_id,
                                end_id=secret_name,
                                kind=edge_kind,
                                properties={
                                    "source": "privilege_escalation_analysis",
                                    "permission": perm,
                                    "role": role,
                                    "risklevel": risk_level,
                                    "projectcontext": project_id,
                                    "attackvector": get_attack_vector_for_permission(perm),
                                    "description": f"{member_id} can access secret {secret_name} via {perm}"
                                }
                            )
                            if success:
                                edges_created += 1
                            else:
                                edges_skipped += 1

    print(f"[+] Built {edges_created} privilege escalation edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid privilege escalation edges")
    return edges


def validate_edges_post_build(edges, debug=False):
    """Post-build validation of edges"""
    valid_edges = 0
    invalid_edges = 0
    for edge in edges:
        start_id = edge.get('start', {}).get('value')
        end_id = edge.get('end', {}).get('value')
        kind = edge.get('kind')
        if start_id and end_id and kind:
            valid_edges += 1
        else:
            invalid_edges += 1
            if debug:
                print(f"[DEBUG] Invalid edge: start='{start_id}', end='{end_id}', kind='{kind}'")
    print(f"[+] Edge validation summary: {valid_edges} valid, {invalid_edges} invalid")
    return valid_edges, invalid_edges


def get_edge_statistics(edges):
    """Get detailed statistics about created edges"""
    edge_kinds = {}
    risk_levels = {}
    for edge in edges:
        kind = edge.get('kind', 'Unknown')
        risk = edge.get('properties', {}).get('risklevel', 'Unknown')
        edge_kinds[kind] = edge_kinds.get(kind, 0) + 1
        risk_levels[risk] = risk_levels.get(risk, 0) + 1
    print(f"[+] Edge Statistics:")
    print(f"    Edge Types: {dict(sorted(edge_kinds.items(), key=lambda x: x[1], reverse=True))}")
    print(f"    Risk Levels: {dict(sorted(risk_levels.items(), key=lambda x: x[1], reverse=True))}")
    return edge_kinds, risk_levels
