let token = null;

async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const statusEl = document.getElementById("login-status");

  try {
    const resp = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username, password })
    });

    if (!resp.ok) {
      statusEl.textContent = "Login failed: " + resp.status;
      return;
    }

    const data = await resp.json();
    token = data.access_token;
    statusEl.textContent = "Logged in. Token stored in memory.";
  } catch (err) {
    statusEl.textContent = "Error: " + err;
  }
}

async function createLink() {
  const statusEl = document.getElementById("create-status");
  if (!token) {
    statusEl.textContent = "Please login first.";
    return;
  }

  const payload = {
    amount: Number(document.getElementById("amount").value),
    currency: document.getElementById("currency").value,
    description: document.getElementById("description").value,
    customer_email: document.getElementById("customer-email").value || null,
    expires_in_minutes: document.getElementById("expires").value
      ? Number(document.getElementById("expires").value)
      : null,
    processor: document.getElementById("processor").value
  };

  try {
    const resp = await fetch("/payment-links", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token
      },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      statusEl.textContent = "Create failed: " + resp.status;
      return;
    }

    const data = await resp.json();
    statusEl.textContent = "Created link with id " + data.id;
    await loadLinks();
  } catch (err) {
    statusEl.textContent = "Error: " + err;
  }
}

async function loadLinks() {
  const listEl = document.getElementById("links-list");
  if (!token) {
    listEl.textContent = "Please login first.";
    return;
  }

  try {
    const resp = await fetch("/payment-links", {
      headers: { Authorization: "Bearer " + token }
    });

    if (!resp.ok) {
      listEl.textContent = "Failed to load: " + resp.status;
      return;
    }

    const data = await resp.json();
    listEl.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    listEl.textContent = "Error: " + err;
  }
}

document.getElementById("login-btn").addEventListener("click", login);
document.getElementById("create-link-btn").addEventListener("click", createLink);
document.getElementById("refresh-links-btn").addEventListener("click", loadLinks);
