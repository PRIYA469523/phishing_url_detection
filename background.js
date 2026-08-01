chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    fetch(`http://127.0.0.1:5000/predict?url=${encodeURIComponent(tab.url)}`)
      .then(response => response.json())
      .then(data => {
        if (data.result === "Phishing") {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: 'Phishing Warning',
            message: `This site may be unsafe:\n${tab.url}`,
            priority: 2
          });
        }
      })
      .catch(error => console.log('Detection failed:', error));
  }
});