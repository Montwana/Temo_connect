document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  try {
    const res = await fetch("http://localhost:5000/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      alert(data.error || "Login failed");
      return;
    }

    // Save token for future requests
    localStorage.setItem("token", data.token);

    // Redirect based on role
    if (data.user.role === "consumer") {
      window.location.href = "consumer-home.html"; // 👈 consumer home
    } else if (data.user.role === "farmer") {
      window.location.href = "farmer-home.html";
    } else if (data.user.role === "admin") {
      window.location.href = "admin-dashboard.html";
    }
  } catch (err) {
    console.error("Error:", err);
    alert("Server error. Try again later.");
  }
});
