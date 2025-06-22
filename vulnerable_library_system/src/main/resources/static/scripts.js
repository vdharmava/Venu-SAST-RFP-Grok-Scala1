// Vuln 55: CWE-620 - Unverified Password Change
function changePassword() {
    let newPass = prompt("New Password:");
    fetch('/change_password', { method: 'POST', body: newPass });
}

// Vuln 56: CWE-200 - Information Exposure
console.log("API Key: hardcoded_api_key_123");