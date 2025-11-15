document.getElementById("urlForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  const url = document.getElementById("urlInput").value;
  const resultBox = document.getElementById("result");
  const scoreBar = document.getElementById("scoreBar");
  const domain = document.getElementById("domain");
  const score = document.getElementById("score");
  const reasons = document.getElementById("reasons");

  const response = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  const data = await response.json();

  if (data.error) {
    alert(data.error);
    return;
  }

  domain.textContent = data.domain;
  score.textContent = `${data.score}%`;

  // Update score bar
  const bar = scoreBar.querySelector("::after");
  scoreBar.style.setProperty("--score", `${data.score}%`);
  scoreBar.innerHTML = ""; // Clear previous
  const fill = document.createElement("div");
  fill.style.width = `${data.score}%`;
  fill.style.height = "100%";
  fill.style.borderRadius = "10px";
  fill.style.backgroundColor =
    data.score < 30 ? "#88e003" : data.score < 70 ? "#f0c000" : "#ff0033";
  scoreBar.appendChild(fill);

  // Show reasons
  reasons.innerHTML = "";
  data.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasons.appendChild(li);
  });

  resultBox.classList.remove("hidden");
});
