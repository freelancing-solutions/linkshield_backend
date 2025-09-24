# Dashboard API Test Plan

## Test Strategy

### Test Categories
1. **Unit Tests** - Individual method testing
2. **Integration Tests** - API endpoint testing
3. **Security Tests** - Access control and validation
4. **Performance Tests** - Load and stress testing
5. **Subscription Tests** - Plan limit enforcement

## Unit Test Cases

### DashboardController Tests

#### Test: get_dashboard_overview
```python
def test_get_dashboard_overview_success():
    """Test successful dashboard overview retrieval"""
    # Arrange
    user = create_test_user()
    projects = create_test_projects(user, count=3)
    
    # Act
    result = controller.get_dashboard_overview(user)
    
    # Assert
    assert result.total_projects == 3
    assert result.active_projects >= 0
    assert result.subscription_status == "active"
    assert result.usage_stats is not None

def test_get_dashboard_overview_no_projects():
    """Test dashboard overview with no projects"""
    # Arrange
    user = create_test_user()
    
    # Act
    result = controller.get_dashboard_overview(user)
    
    # Assert
    assert result.total_projects == 0
    assert result.active_projects == 0
    assert result.recent_alerts == 0
```

#### Test: list_projects
```python
def test_list_projects_pagination():
    """Test project listing with pagination"""
    # Arrange
    user = create_test_user()
    projects = create_test_projects(user, count=25)
    
    # Act - Page 1
    page1 = controller.list_projects(user, page=1, limit=10)
    
    # Act - Page 2
    page2 = controller.list_projects(user, page=2, limit=10)
    
    # Assert
    assert len(page1) == 10
    assert len(page2) == 10
    assert page1[0].id != page2[0].id

def test_list_projects_search():
    """Test project search functionality"""
    # Arrange
    user = create_test_user()
    project1 = create_project(user, name="Website Monitor")
    project2 = create_project(user, name="API Monitor")
    
    # Act
    results = controller.list_projects(user, search="Website")
    
    # Assert
    assert len(results) == 1
    assert results[0].name == "Website Monitor"

def test_list_projects_status_filter():
    """Test project filtering by status"""
    # Arrange
    user = create_test_user()
    active_project = create_project(user, is_active=True)
    inactive_project = create_project(user, is_active=False)
    
    # Act
    active_results = controller.list_projects(user, status_filter="active")
    inactive_results = controller.list_projects(user, status_filter="inactive")
    
    # Assert
    assert len(active_results) == 1
    assert len(inactive_results) == 1
    assert active_results[0].is_active == True
    assert inactive_results[0].is_active == False
```

#### Test: create_project
```python
def test_create_project_success():
    """Test successful project creation"""
    # Arrange
    user = create_test_user()
    subscription = create_subscription(user, plan="pro")
    
    # Act
    project = controller.create_project(
        user=user,
        name="Test Project",
        description="Test Description",
        website_url="https://example.com"
    )
    
    # Assert
    assert project.name == "Test Project"
    assert project.domain == "example.com"
    assert project.monitoring_enabled == True
    assert project.member_count == 1  # Owner

def test_create_project_subscription_limit():
    """Test project creation with subscription limit"""
    # Arrange
    user = create_test_user()
    subscription = create_subscription(user, plan="free", project_limit=1)
    existing_project = create_project(user)
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.create_project(
            user=user,
            name="Second Project",
            description="Should fail",
            website_url="https://test.com"
        )
    
    assert exc_info.value.status_code == 400
    assert "subscription limit" in exc_info.value.detail.lower()

def test_create_project_invalid_url():
    """Test project creation with invalid URL"""
    # Arrange
    user = create_test_user()
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.create_project(
            user=user,
            name="Test Project",
            description="Test",
            website_url="invalid-url"
        )
    
    assert exc_info.value.status_code == 400
```

#### Test: get_project
```python
def test_get_project_success():
    """Test successful project retrieval"""
    # Arrange
    user = create_test_user()
    project = create_project(user)
    
    # Act
    result = controller.get_project(user, project.id)
    
    # Assert
    assert result.id == project.id
    assert result.name == project.name
    assert result.member_count >= 1

def test_get_project_not_found():
    """Test project retrieval with non-existent ID"""
    # Arrange
    user = create_test_user()
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.get_project(user, uuid4())
    
    assert exc_info.value.status_code == 404

def test_get_project_access_denied():
    """Test project retrieval without access"""
    # Arrange
    owner = create_test_user()
    other_user = create_test_user()
    project = create_project(owner)
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.get_project(other_user, project.id)
    
    assert exc_info.value.status_code == 403
```

#### Test: update_project
```python
def test_update_project_success():
    """Test successful project update"""
    # Arrange
    user = create_test_user()
    project = create_project(user)
    
    # Act
    updated = controller.update_project(
        user=user,
        project_id=project.id,
        name="Updated Name",
        description="Updated Description"
    )
    
    # Assert
    assert updated.name == "Updated Name"
    assert updated.description == "Updated Description"

def test_update_project_permissions():
    """Test project update permissions"""
    # Arrange
    owner = create_test_user()
    editor = create_test_user()
    project = create_project(owner)
    add_project_member(project, editor, role="editor")
    
    # Act - Editor can update
    updated = controller.update_project(
        user=editor,
        project_id=project.id,
        name="Editor Updated"
    )
    
    # Assert
    assert updated.name == "Editor Updated"

def test_update_project_viewer_denied():
    """Test project update with viewer role"""
    # Arrange
    owner = create_test_user()
    viewer = create_test_user()
    project = create_project(owner)
    add_project_member(project, viewer, role="viewer")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.update_project(
            user=viewer,
            project_id=project.id,
            name="Should Fail"
        )
    
    assert exc_info.value.status_code == 403
```

#### Test: delete_project
```python
def test_delete_project_success():
    """Test successful project deletion"""
    # Arrange
    user = create_test_user()
    project = create_project(user)
    
    # Act
    result = controller.delete_project(user, project.id)
    
    # Assert
    assert result is True
    assert project.is_active == False

def test_delete_project_non_owner_denied():
    """Test project deletion by non-owner"""
    # Arrange
    owner = create_test_user()
    editor = create_test_user()
    project = create_project(owner)
    add_project_member(project, editor, role="editor")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.delete_project(editor, project.id)
    
    assert exc_info.value.status_code == 403
```

#### Test: toggle_monitoring
```python
def test_toggle_monitoring_enable():
    """Test enabling project monitoring"""
    # Arrange
    user = create_test_user()
    project = create_project(user, monitoring_enabled=False)
    
    # Act
    result = controller.toggle_monitoring(user, project.id, enabled=True)
    
    # Assert
    assert result.monitoring_enabled == True
    assert result.monitoring_config is not None

def test_toggle_monitoring_disable():
    """Test disabling project monitoring"""
    # Arrange
    user = create_test_user()
    project = create_project(user, monitoring_enabled=True)
    
    # Act
    result = controller.toggle_monitoring(user, project.id, enabled=False)
    
    # Assert
    assert result.monitoring_enabled == False

def test_toggle_monitoring_no_access():
    """Test monitoring toggle without access"""
    # Arrange
    owner = create_test_user()
    other_user = create_test_user()
    project = create_project(owner)
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.toggle_monitoring(other_user, project.id, enabled=True)
    
    assert exc_info.value.status_code == 403
```

#### Test: list_project_members
```python
def test_list_project_members_success():
    """Test listing project members"""
    # Arrange
    owner = create_test_user()
    member1 = create_test_user(email="member1@test.com")
    member2 = create_test_user(email="member2@test.com")
    project = create_project(owner)
    add_project_member(project, member1, role="editor")
    add_project_member(project, member2, role="viewer")
    
    # Act
    members = controller.list_project_members(owner, project.id)
    
    # Assert
    assert len(members) == 3  # Owner + 2 members
    assert any(m.email == "member1@test.com" for m in members)
    assert any(m.role == "editor" for m in members)

def test_list_project_members_no_access():
    """Test listing members without access"""
    # Arrange
    owner = create_test_user()
    other_user = create_test_user()
    project = create_project(owner)
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.list_project_members(other_user, project.id)
    
    assert exc_info.value.status_code == 403
```

#### Test: invite_team_member
```python
def test_invite_team_member_success():
    """Test successful team member invitation"""
    # Arrange
    owner = create_test_user()
    project = create_project(owner)
    subscription = create_subscription(owner, plan="pro", team_member_limit=5)
    
    # Act
    invitation = controller.invite_team_member(
        user=owner,
        project_id=project.id,
        email="newmember@test.com",
        role="editor"
    )
    
    # Assert
    assert invitation.email == "newmember@test.com"
    assert invitation.role == "editor"
    assert invitation.status == "pending"

def test_invite_team_member_subscription_limit():
    """Test invitation with subscription limit"""
    # Arrange
    owner = create_test_user()
    project = create_project(owner)
    subscription = create_subscription(owner, plan="free", team_member_limit=2)
    existing_member = create_test_user(email="existing@test.com")
    add_project_member(project, existing_member, role="editor")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.invite_team_member(
            user=owner,
            project_id=project.id,
            email="newmember@test.com",
            role="viewer"
        )
    
    assert exc_info.value.status_code == 400
    assert "subscription limit" in exc_info.value.detail.lower()

def test_invite_team_member_duplicate():
    """Test duplicate invitation"""
    # Arrange
    owner = create_test_user()
    existing_member = create_test_user(email="existing@test.com")
    project = create_project(owner)
    add_project_member(project, existing_member, role="editor")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        controller.invite_team_member(
            user=owner,
            project_id=project.id,
            email="existing@test.com",
            role="viewer"
        )
    
    assert exc_info.value.status_code == 409
    assert "already a member" in exc_info.value.detail.lower()

def test_invite_team_member_permissions():
    """Test invitation permissions"""
    # Arrange
    owner = create_test_user()
    editor = create_test_user()
    project = create_project(owner)
    add_project_member(project, editor, role="editor")
    
    # Act - Editor can invite
    invitation = controller.invite_team_member(
        user=editor,
        project_id=project.id,
        email="newmember@test.com",
        role="viewer"
    )
    
    # Assert
    assert invitation.role == "viewer"
```

## Integration Test Cases

### API Endpoint Tests

#### Test: Dashboard Overview API
```python
def test_dashboard_overview_api(client, auth_token):
    """Test dashboard overview endpoint"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Act
    response = client.get("/dashboard/overview", headers=headers)
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert "total_projects" in data
    assert "active_projects" in data
    assert "subscription_status" in data
    assert "usage_stats" in data
```

#### Test: Project CRUD API
```python
def test_project_crud_flow(client, auth_token):
    """Test complete project CRUD flow"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create project
    create_data = {
        "name": "Test Project",
        "description": "Test Description",
        "website_url": "https://test.com"
    }
    
    # Act - Create
    create_response = client.post(
        "/dashboard/projects",
        json=create_data,
        headers=headers
    )
    
    # Assert - Create
    assert create_response.status_code == 201
    project_id = create_response.json()["id"]
    
    # Act - Get
    get_response = client.get(f"/dashboard/projects/{project_id}", headers=headers)
    
    # Assert - Get
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Test Project"
    
    # Act - Update
    update_data = {"name": "Updated Project"}
    update_response = client.patch(
        f"/dashboard/projects/{project_id}",
        json=update_data,
        headers=headers
    )
    
    # Assert - Update
    assert update_response.status_code == 200
    assert update_response.json()["name"] == "Updated Project"
    
    # Act - Delete
    delete_response = client.delete(f"/dashboard/projects/{project_id}", headers=headers)
    
    # Assert - Delete
    assert delete_response.status_code == 200
```

#### Test: Team Management API
```python
def test_team_invitation_flow(client, auth_token):
    """Test team invitation and acceptance flow"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create project
    project_data = {
        "name": "Team Project",
        "description": "Team Test",
        "website_url": "https://team.com"
    }
    create_response = client.post(
        "/dashboard/projects",
        json=project_data,
        headers=headers
    )
    project_id = create_response.json()["id"]
    
    # Act - Invite member
    invite_data = {
        "email": "teammate@example.com",
        "role": "editor"
    }
    invite_response = client.post(
        f"/dashboard/projects/{project_id}/members/invite",
        json=invite_data,
        headers=headers
    )
    
    # Assert - Invite
    assert invite_response.status_code == 200
    assert invite_response.json()["email"] == "teammate@example.com"
    assert invite_response.json()["status"] == "pending"
```

## Security Test Cases

### Access Control Tests

#### Test: Unauthorized Access
```python
def test_unauthorized_access(client):
    """Test access without authentication"""
    # Act
    response = client.get("/dashboard/overview")
    
    # Assert
    assert response.status_code == 401

def test_invalid_token_access(client):
    """Test access with invalid token"""
    # Arrange
    headers = {"Authorization": "Bearer invalid-token"}
    
    # Act
    response = client.get("/dashboard/overview", headers=headers)
    
    # Assert
    assert response.status_code == 401
```

#### Test: Cross-User Access
```python
def test_cross_user_project_access(client, auth_token, other_auth_token):
    """Test accessing another user's project"""
    # Arrange
    headers1 = {"Authorization": f"Bearer {auth_token}"}
    headers2 = {"Authorization": f"Bearer {other_auth_token}"}
    
    # Create project as user1
    project_data = {
        "name": "Private Project",
        "description": "Private",
        "website_url": "https://private.com"
    }
    create_response = client.post(
        "/dashboard/projects",
        json=project_data,
        headers=headers1
    )
    project_id = create_response.json()["id"]
    
    # Act - User2 tries to access
    response = client.get(f"/dashboard/projects/{project_id}", headers=headers2)
    
    # Assert
    assert response.status_code == 403
```

### Input Validation Tests

#### Test: Invalid Input Data
```python
def test_invalid_project_data(client, auth_token):
    """Test project creation with invalid data"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Act - Invalid URL
    invalid_data = {
        "name": "Test",
        "description": "Test",
        "website_url": "not-a-url"
    }
    response = client.post("/dashboard/projects", json=invalid_data, headers=headers)
    
    # Assert
    assert response.status_code == 422

def test_invalid_email_invitation(client, auth_token):
    """Test invitation with invalid email"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create project first
    project_data = {
        "name": "Test Project",
        "description": "Test",
        "website_url": "https://test.com"
    }
    create_response = client.post(
        "/dashboard/projects",
        json=project_data,
        headers=headers
    )
    project_id = create_response.json()["id"]
    
    # Act - Invalid email
    invite_data = {
        "email": "invalid-email",
        "role": "editor"
    }
    response = client.post(
        f"/dashboard/projects/{project_id}/members/invite",
        json=invite_data,
        headers=headers
    )
    
    # Assert
    assert response.status_code == 422
```

## Performance Test Cases

### Load Testing

#### Test: Concurrent Project Creation
```python
def test_concurrent_project_creation(client, auth_token):
    """Test concurrent project creation"""
    # Arrange
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Act - Create multiple projects concurrently
    def create_project(i):
        project_data = {
            "name": f"Concurrent Project {i}",
            "description": f"Test {i}",
            "website_url": f"https://test{i}.com"
        }
        return client.post(
            "/dashboard/projects",
            json=project_data,
            headers=headers
        )
    
    # Execute concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(create_project, i) for i in range(5)]
        responses = [f.result() for f in futures]
    
    # Assert
    success_count = sum(1 for r in responses if r.status_code == 201)
    assert success_count >= 3  # At least 3 should succeed
```

#### Test: Large Dataset Pagination
```python
def test_large_dataset_pagination(client, auth_token):
    """Test pagination with large dataset"""
    # Arrange - Create many projects
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create 100 projects
    for i in range(100):
        project_data = {
            "name": f"Bulk Project {i}",
            "description": f"Test {i}",
            "website_url": f"https://bulk{i}.com"
        }
        client.post("/dashboard/projects", json=project_data, headers=headers)
    
    # Act - Paginate through results
    page1_response = client.get("/dashboard/projects?page=1&limit=20", headers=headers)
    page2_response = client.get("/dashboard/projects?page=2&limit=20", headers=headers)
    
    # Assert
    assert page1_response.status_code == 200
    assert page2_response.status_code == 200
    assert len(page1_response.json()) == 20
    assert len(page2_response.json()) == 20
```

## Test Execution Plan

### Test Environment Setup
```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-mock httpx

# Setup test database
export TEST_DATABASE_URL="postgresql://test_user:test_pass@localhost/test_db"

# Run all tests
pytest tests/dashboard/ -v --cov=src.controllers.dashboard_controller

# Run specific test categories
pytest tests/dashboard/test_unit.py -v
pytest tests/dashboard/test_integration.py -v
pytest tests/dashboard/test_security.py -v
pytest tests/dashboard/test_performance.py -v
```

### Test Data Setup
```python
# Test fixtures for consistent test data
@pytest.fixture
def test_user():
    return create_test_user(email="test@example.com")

@pytest.fixture
def auth_token(test_user):
    return generate_auth_token(test_user)

@pytest.fixture
def test_project(test_user):
    return create_project(test_user, name="Test Project")

@pytest.fixture
def subscription_limits():
    return {
        "free": {"projects": 1, "team_members": 2},
        "pro": {"projects": 10, "team_members": 10},
        "enterprise": {"projects": -1, "team_members": -1}
    }
```

### Success Criteria
- **Unit Tests**: 95%+ code coverage
- **Integration Tests**: All endpoints tested
- **Security Tests**: No unauthorized access vulnerabilities
- **Performance Tests**: < 200ms average response time
- **Subscription Tests**: All limits properly enforced

This comprehensive test plan ensures the Dashboard API is robust, secure, and performs well under various conditions while maintaining subscription compliance.