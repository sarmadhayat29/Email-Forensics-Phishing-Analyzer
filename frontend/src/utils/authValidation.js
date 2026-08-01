/** Shared client-side auth form validation (login + signup). */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(email) {
  const value = (email || "").trim();
  if (!value) return "Email address is required.";
  if (!EMAIL_RE.test(value)) return "Invalid email address.";
  return null;
}

export function validateFullName(fullName) {
  const value = (fullName || "").trim();
  if (!value) return "Full name is required.";
  if (value.length < 2) return "Full name must be at least 2 characters.";
  return null;
}

export function validatePassword(password, { requireMinLength = true } = {}) {
  if (password == null || password === "") return "Password is required.";
  if (password !== password.trim()) {
    return "Password cannot start or end with spaces.";
  }
  if (requireMinLength && password.length < 8) {
    return "Password must be at least 8 characters.";
  }
  return null;
}

export function validateConfirmPassword(password, confirmPassword) {
  if (confirmPassword == null || confirmPassword === "") {
    return "Confirm password is required.";
  }
  if (password !== confirmPassword) return "Passwords do not match.";
  return null;
}

/** Password strength for optional UI hint: weak | fair | strong */
export function passwordStrength(password) {
  if (!password) return { level: "empty", label: "", score: 0 };
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  if (score <= 2) return { level: "weak", label: "Weak", score };
  if (score <= 3) return { level: "fair", label: "Fair", score };
  return { level: "strong", label: "Strong", score };
}

export function validateLoginForm({ email, password }) {
  const errors = {
    email: validateEmail(email),
    password: validatePassword(password, { requireMinLength: false }),
  };
  return {
    errors,
    isValid: !errors.email && !errors.password,
  };
}

export function validateSignupForm({ fullName, email, password, confirmPassword }) {
  const errors = {
    fullName: validateFullName(fullName),
    email: validateEmail(email),
    password: validatePassword(password, { requireMinLength: true }),
    confirmPassword: validateConfirmPassword(password, confirmPassword),
  };
  return {
    errors,
    isValid: !errors.fullName && !errors.email && !errors.password && !errors.confirmPassword,
  };
}
