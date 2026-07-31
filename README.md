# Phishing-
ML-Based Phishing URL Detector is a cybersecurity project designed to identify malicious phishing URLs using machine learning algorithms. It includes a user-friendly web dashboard where users can enter a URL and receive instant predictions, helping improve awareness and online security.

## System Architecture

![System Architecture](images/architecture.png.jpeg)

This diagram shows the flow of the system - from URL input, through feature extraction (30 features across 4 categories), to prediction by the trained XGBoost model, and finally the Safe/Phishing result show to the user.

# Demo 
### Phishing URLs detected

![Phishing Example 1](images/phishing_e1.png)
![Phishing Example 2](images/phishing_e2.png)
![Phishing Example with Explanation](images/phishing_e3.png)

### Safe URLs detected

![Safe Example 1](images/safe_e1.png)
![Safe Example with Explanation](images/safe_e2.png)

The last two examples above also show SHAP explainability — the bar chart next to each prediction shows which features drove the decision. 

Red bars push the prediction toward "phishing," green bars push it toward "safe." This makes the model's decisions transparent instead of a black box.

## My Contribution (Feature Extraction and Web App)

As Person B on this project, my main contribution was building the live feature extraction module, which converts any new URL entered by a user into the 30 features required by our trained model. Nine of these features were straightforward to extract directly from the URL text itself — for example, checking for IP addresses, "@" symbols, excessive sub-domains, or the use of URL-shortening services. Four features required live internet lookups, using libraries like python-whois and dnspython to check domain age, domain registration length, SSL certificate status, and DNS records. The remaining four features (such as web traffic rank and Google index status) depend on services like Alexa, which was officially shut down in 2022, so these were implemented to safely return a neutral/unknown value instead of breaking the app. This module was then connected to a Streamlit web app, allowing a user to paste a URL and instantly see a Phishing/Safe prediction along with the underlying feature values.
