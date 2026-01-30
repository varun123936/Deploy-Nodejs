# Backend API Test Script
$baseUrl = "http://localhost:3000"
$headers = @{
    "Content-Type" = "application/json"
}

Write-Host "`n=== Testing Backend API ===`n" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "1. Testing Health Endpoint..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/health" -Method GET
    Write-Host "   ✓ Health check passed: $($response.message)" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Health check failed: $_" -ForegroundColor Red
    exit 1
}

# Test 2: Register User
Write-Host "`n2. Testing Register Endpoint..." -ForegroundColor Yellow
$registerData = @{
    username = "testuser_$(Get-Date -Format 'yyyyMMddHHmmss')"
    email = "test_$(Get-Date -Format 'yyyyMMddHHmmss')@example.com"
    password = "password123"
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method POST -Body $registerData -Headers $headers
    Write-Host "   ✓ Registration successful!" -ForegroundColor Green
    Write-Host "   User ID: $($registerResponse.data.user.id)" -ForegroundColor Gray
    Write-Host "   Username: $($registerResponse.data.user.username)" -ForegroundColor Gray
    $testUsername = ($registerData | ConvertFrom-Json).username
    $testEmail = ($registerData | ConvertFrom-Json).email
} catch {
    Write-Host "   ✗ Registration failed: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorObj = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Error: $($errorObj.message)" -ForegroundColor Red
    }
    exit 1
}

# Test 3: Login
Write-Host "`n3. Testing Login Endpoint..." -ForegroundColor Yellow
$loginData = @{
    username = $testUsername
    password = "password123"
} | ConvertTo-Json

$session = $null
try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $loginData -Headers $headers -SessionVariable session
    Write-Host "   ✓ Login successful!" -ForegroundColor Green
    Write-Host "   Access Token received: $($loginResponse.data.accessToken.Substring(0, 20))..." -ForegroundColor Gray
    $accessToken = $loginResponse.data.accessToken
    $authHeaders = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $accessToken"
    }
} catch {
    Write-Host "   ✗ Login failed: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorObj = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Error: $($errorObj.message)" -ForegroundColor Red
    }
    exit 1
}

# Test 4: Get Current User (Protected Route)
Write-Host "`n4. Testing Protected Route (/auth/me)..." -ForegroundColor Yellow
try {
    $meResponse = Invoke-RestMethod -Uri "$baseUrl/auth/me" -Method GET -Headers $authHeaders
    Write-Host "   ✓ Protected route access successful!" -ForegroundColor Green
    Write-Host "   User: $($meResponse.data.user.username) ($($meResponse.data.user.email))" -ForegroundColor Gray
} catch {
    Write-Host "   ✗ Protected route failed: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorObj = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Error: $($errorObj.message)" -ForegroundColor Red
    }
}

# Test 5: Refresh Token
Write-Host "`n5. Testing Refresh Token Endpoint..." -ForegroundColor Yellow
try {
    $refreshResponse = Invoke-RestMethod -Uri "$baseUrl/auth/refresh" -Method POST -WebSession $session -Headers @{"Content-Type" = "application/json"}
    Write-Host "   ✓ Token refresh successful!" -ForegroundColor Green
    Write-Host "   New Access Token received: $($refreshResponse.data.accessToken.Substring(0, 20))..." -ForegroundColor Gray
    $accessToken = $refreshResponse.data.accessToken
} catch {
    Write-Host "   ✗ Token refresh failed: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorObj = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Error: $($errorObj.message)" -ForegroundColor Red
    }
}

# Test 6: Logout
Write-Host "`n6. Testing Logout Endpoint..." -ForegroundColor Yellow
try {
    $logoutResponse = Invoke-RestMethod -Uri "$baseUrl/auth/logout" -Method POST -WebSession $session -Headers @{"Content-Type" = "application/json"}
    Write-Host "   ✓ Logout successful!" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Logout failed: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorObj = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Error: $($errorObj.message)" -ForegroundColor Red
    }
}

# Test 7: Try accessing protected route after logout (should fail)
Write-Host "`n7. Testing Protected Route After Logout (should fail)..." -ForegroundColor Yellow
try {
    $meResponse = Invoke-RestMethod -Uri "$baseUrl/auth/me" -Method GET -Headers $authHeaders
    Write-Host "   ⚠ Protected route still accessible (unexpected)" -ForegroundColor Yellow
} catch {
    Write-Host "   ✓ Protected route correctly rejected (expected)" -ForegroundColor Green
}

Write-Host "`n=== All Tests Completed ===`n" -ForegroundColor Cyan
