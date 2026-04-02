const AuthGuard = {
  rules: {
    employee: ['dashboard', 'profile', 'attendance', 'leave'],
    hr:       ['dashboard', 'profile', 'attendance', 'leave', 
                'hr-attendance', 'hr-leave', 'hr-reports'],
    admin:    ['dashboard', 'profile', 'attendance', 'leave',
                'hr-attendance', 'hr-leave', 'hr-reports',
                'admin-users', 'admin-logs'],
  },

  isAuthenticated() {
    return !!currentUser && !!localStorage.getItem('access_token');
  },

  canAccess(page) {
    if (!this.isAuthenticated()) return false;
    const allowed = this.rules[currentUser.role] ?? [];
    return allowed.includes(page);
  },

  enforce(page) {
    if (!this.isAuthenticated()) { doLogout(); return false; }
    if (!this.canAccess(page)) {
      toast(`Access denied: "${page}"`, 'error');
      if (page !== 'dashboard') showPage('dashboard');
      return false;
    }
    return true;
  },

  restoreSession() {
    const token = localStorage.getItem('access_token');
    const saved  = localStorage.getItem('current_user');
    if (!token || !saved) return false;
    try {
      currentUser = JSON.parse(saved);
      return true;
    } catch { return false; }
  },
};
