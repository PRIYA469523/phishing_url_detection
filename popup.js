document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;
    document.getElementById('current-url').innerText = currentUrl;

    document.getElementById('checkBtn').addEventListener('click', function () {
      const resultDiv = document.getElementById('result');
      resultDiv.innerText = "Checking...";
      resultDiv.className = "";

      fetch(`http://127.0.0.1:5000/predict?url=${encodeURIComponent(currentUrl)}`)
        .then(response => response.json())
        .then(data => {
          if (data.result === "Phishing") {
            resultDiv.innerText = "Warning: Phishing site detected!";
            resultDiv.className = "phishing";
          } else {
            resultDiv.innerText = "Safe: This site looks legitimate.";
            resultDiv.className = "legitimate";
          }
        })
        .catch(error => {
          resultDiv.innerText = "Error: Could not reach detection server.";
          resultDiv.className = "phishing";
        });
    });
  });
});