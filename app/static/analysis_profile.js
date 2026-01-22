console.log("analysis_profile.js loaded");

window.ftAnalysisInitProfile = function(ctx) {
    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            fetch('/users/logout', {
                method: 'POST',
                credentials: 'include'
            }).then(response => {
                if (response.ok) {
                    window.location.href = '/';
                }
            });
        });
    }

    const profileChangePasswordBtn = document.getElementById('profileChangePassword');
    if (profileChangePasswordBtn) {
        profileChangePasswordBtn.addEventListener('click', function() {
            window.location.href = '/users/reset-password';
        });
    }
};
