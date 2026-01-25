console.log("analysis_profile.js loaded");

window.ftAnalysisInitProfile = function(ctx) {
    const logoutButtons = [
        document.getElementById('profileLogout'),
        document.getElementById('logoutBtn'),
    ].filter(Boolean);

    logoutButtons.forEach((btn) => {
        btn.addEventListener('click', async function() {
            try {
                const response = await fetch('/users/logout', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (response.ok) {
                    window.location.href = '/';
                }
            } catch (e) {
                console.error('Logout error:', e);
            }
        });
    });

    const profileChangePasswordBtn = document.getElementById('profileChangePassword');
    if (profileChangePasswordBtn) {
        profileChangePasswordBtn.addEventListener('click', function() {
            window.location.href = '/users/reset-password';
        });
    }
};
