
## **Why KQL Maps Are Essential for CEOs and Non-Tech People** 🌍📊

A KQL map transforms complex data into clear, actionable visuals, making it easier to spot trends, manage risks, and make informed decisions.  

- **Spot Trends Quickly**: See where activity is happening globally, from customer logins to potential risks.  
- **Strengthen Security**: Identify unusual activity in real time to stay ahead of threats.  
- **Simplify Data**: Turn overwhelming data into easy-to-understand visuals for your leadership team.  
- **Act Proactively**: Get real-time insights to respond faster to opportunities and challenges.  

Think of it as your business’s GPS for navigating data smarter and faster. 🚀
---

---
## **1. KQL-Map-Malicious-Traffic-Entering-the-Network**

![Screenshot 2025-01-13 121331](https://github.com/user-attachments/assets/6b9a1268-3aa5-41e0-8dcf-680e27572432)

---

This query helps you track **malicious network flows** in Azure and enriches the data with **geolocation details**. Here’s a breakdown 🌐.
---

### **Your KQL Query**  

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
//| where SrcIP_s == "10.0.0.5" 
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```

This query helps you track **malicious network flows** in Azure and enriches the data with **geolocation details**. Here’s a breakdown:

1. **GeoIP Watchlist** 🌍:  
   `let GeoIPDB_FULL = _GetWatchlist("geoip");`  
   This loads a geo-location database to map IP addresses to geographic details like country, city, latitude, and longitude.

2. **Filtering Malicious Flows** ⚠️:  
   The `AzureNetworkAnalytics_CL` table is filtered to identify malicious flows:
   - **`FlowType_s == "MaliciousFlow"`** 🔴: Filters the data to only include malicious flows.

3. **Sorting and Selecting Data** 🔢:  
   - **`order by TimeGenerated desc`** ⏳: Orders the flows by the most recent time.
   - **`project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;`** 📝: Selects the relevant fields: 
     - **TimeGenerated** 🕒: When the flow was detected.
     - **FlowType** ⚡: Type of flow (in this case, "MaliciousFlow").
     - **IpAddress** 🌐: The source IP address.
     - **DestinationIpAddress** 🌍: The destination IP address.
     - **DestinationPort** 🔌: The destination port.
     - **Protocol** 🔐: The layer 7 protocol used (HTTP, etc.).
     - **NSGRuleMatched** 🛡️: Any Network Security Group rules that were triggered.

4. **GeoIP Enrichment** 🌍🔍:  
   The query enriches the malicious flow data by using the `ipv4_lookup` function to find geographic details based on the source IP address:
   - **`evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)`** 🌍: This function adds location details (city, country, latitude, longitude) for the source IP address.

5. **Data Projection** 🎯:  
   The query then selects the final output fields:
   - **TimeGenerated** 🕒: When the flow occurred.
   - **FlowType** ⚡: Type of flow.
   - **IpAddress** 🌐: Source IP address.
   - **DestinationIpAddress** 🌍: Destination IP address.
   - **DestinationPort** 🔌: Destination port.
   - **Protocol** 🔐: Protocol used.
   - **NSGRuleMatched** 🛡️: NSG rule triggered.
   - **Latitude** 📍 and **Longitude** 🌍: Geographical coordinates.
   - **City** 🏙️: The city associated with the IP.
   - **Country** 🌎: The country associated with the IP.
   - **Friendly_location** 🏷️: A combined label with city and country for better readability.

### Final Output:
This query gives you a detailed view of malicious network flows, including:
- **FlowType** ⚡: The type of flow (malicious).
- **IP Addresses** 🌐🌍: Source and destination IPs.
- **Destination Port** 🔌: The target port.
- **Protocol** 🔐: The type of protocol used.
- **NSG Rule Matched** 🛡️: Which security rules were triggered.
- **Geolocation Information** 🌍📍: City, country, latitude, and longitude for the source IP, helping you track the location of malicious flows in real-time.

This helps identify threats and track malicious activity more effectively by adding geographical context to each event, improving your network security insights.

---

## **2. KQL-Map-Azure-Authentication-Success**

![Screenshot 2025-01-13 111720](https://github.com/user-attachments/assets/214cbc32-7553-4350-b0c8-a196f923a292)
---

To better understand and refine your KQL query for Microsoft Defender and ensure it works seamlessly for your graph visualization, let's break it down step-by-step:  

---

In short, this query provides a count of successful logins, along with details like where the user is logging in from 🌐.
---

### **Your KQL Query**  

```kql
SigninLogs 
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

This query analyzes sign-in logs to give you a clear picture of user activity. Here’s a simple breakdown:  

1. **SigninLogs** 📜: This is where Azure AD sign-in data is stored.  

2. **`where ResultType == 0`** ✅: Filters the data to only include successful sign-ins (ResultType 0 means success).  

3. **`summarize LoginCount = count()`** 🔢: Counts how many successful logins happened and groups them by specific details, such as:  
   - **Identity** 👤: The user who logged in.  
   - **Latitude** 🌍 & **Longitude** 📍: The geographic location of the user’s sign-in.  
   - **City** 🏙️: The city where the sign-in occurred.  
   - **Country** 🌎: The country where the sign-in occurred.  

4. **`project`** 🎯: This step selects and renames the final data you want to display:  
   - **Identity** 👥: The user’s name or ID.  
   - **Latitude & Longitude** 📍🌍: Their location.  
   - **City & Country** 🏙️🌍: Where they logged in from.  
   - **LoginCount** 🔢: The number of successful logins from that user.  
   - **`friendly_label`** 🏷️: A friendly label that combines the user's name with their city and country for easier reference.  

---

CEOs and non-tech people will love this because it turns complex data into easy-to-understand insights 🌍📊. It shows where users are logging in from 🌎, how many successful logins there are 🔢, and provides a clear view of business activity without technical jargon. Perfect for making fast, informed decisions and spotting trends! 💡

---
## **3. KQL-Map-Azure-Authentication-Failures**

![Screenshot 2025-01-13 113750](https://github.com/user-attachments/assets/56d5cf72-d60c-4cb6-8961-1fa431b21c39)

---

This query helps you identify failed sign-ins by analyzing the **SigninLogs** data. Here's a simple breakdown 🌐.
---

### **Your KQL Query**  

```kql
SigninLogs
| where ResultType != 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

1. **SigninLogs** 📜: This is where Azure AD sign-in data is stored.

2. **`where ResultType != 0`** ❌: Filters the data to only include failed sign-ins (ResultType other than 0 means failure).

3. **`summarize LoginCount = count()`** 🔢: Counts the number of failed logins, grouped by specific details, such as:  
   - **Identity** 👤: The user who attempted to log in.
   - **Latitude** 🌍 & **Longitude** 📍: The geographic location of the failed sign-in.
   - **City** 🏙️: The city where the failed sign-in occurred.
   - **Country** 🌎: The country where the failed sign-in occurred.

4. **`project`** 🎯: This step selects and renames the final data you want to display:  
   - **Identity** 👥: The user’s name or ID.
   - **Latitude & Longitude** 📍🌍: Their location.
   - **City & Country** 🏙️🌍: Where the failed sign-in occurred.
   - **LoginCount** 🔢: The number of failed logins from that user.
   - **`friendly_label`** 🏷️: A friendly label that combines the user's name with their city and country for easier reference.

This query gives you a view of failed logins, highlighting potential security concerns, and makes it easier to spot patterns like repeated failed attempts from specific locations 🌐.

---
## **4. KQL-Map-Azure-Resource-Creations**

![Screenshot 2025-01-13 115400](https://github.com/user-attachments/assets/7089d599-eedc-4e57-83e8-02e779289f16)

---
This query helps analyze Azure activity logs related to resource creation and enriches them with geographic details. Here's a breakdown of how it works 🌐.
---

### **Your KQL Query**  


```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, 
          CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
          CallerIpAddress, 
          ResouceCreationCount, 
          Country = countryname, 
          Latitude = latitude, 
          Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```     
---          


1. **GeoIP Watchlist** 🌍:  
   `let GeoIPDB_FULL = _GetWatchlist("geoip");`  
   This loads a geo-location database to map IP addresses to geographic information (like country, city, latitude, and longitude).

2. **Filtering Azure Activity** 🔍:  
   The `AzureActivity` table is filtered to exclude certain caller IDs and only consider valid IP addresses and successful resource creation actions:
   - **`where not(Caller matches regex ...)`** ❌: Filters out logs with GUID caller IDs (usually representing machines or services).
   - **`where CallerIpAddress matches regex ...`** 🌐: Ensures the logs only contain valid IPv4 addresses.
   - **`where OperationNameValue endswith "WRITE" ...`** 📝: Focuses on write operations, like creating or modifying resources, and includes only successful activities.

3. **Summarizing Resource Creation** 🔢:  
   `summarize ResouceCreationCount = count()` groups the data to count how many resource creation actions took place, grouped by:
   - **Caller** 👤: The user or service making the request.
   - **CallerIpAddress** 📶: The IP address used during the request.

4. **GeoIP Enrichment** 🌍🔍:  
   Using the `ipv4_lookup` function, geographic details (such as country, latitude, and longitude) are added to the data by looking up the **GeoIPDB_FULL** watchlist.

5. **Data Projection** 🎯:  
   The query then creates a friendly label and selects the fields to display:
   - **Caller** 👥: The name or ID of the user making the request.
   - **CallerPrefix** 👤: The part before the "@" in the caller's user principal name (UPN).
   - **CallerIpAddress** 🌐: The IP address used during the request.
   - **ResouceCreationCount** 🔢: The count of resource creation actions.
   - **Country** 🌎, **Latitude** 📍, and **Longitude** 🌍: Geographic details about the action.
   - **friendly_label** 🏷️: A user-friendly label combining the caller's name and location for easy reference.

### Final Output:
This enriched query gives you a clearer view of resource creation activity, with geographic context to help identify potential suspicious behavior or patterns:
- **Caller** 👤: Who initiated the action.
- **CallerPrefix** 🧑‍💼: The caller's name before the "@" symbol.
- **CallerIpAddress** 📶: The IP address used.
- **ResourceCreationCount** 🔢: The number of resources created.
- **Country, Latitude, and Longitude** 🌍: Location details to map the activity.
- **friendly_label** 🏷️: A friendly label combining the user's name and location.

This query helps you track resource creation with geographical context, making it easier to spot anomalies or track user activity across different regions.

---
## **5. KQL-Map-VM-Authentication-Failures**

![Screenshot 2025-01-13 121331](https://github.com/user-attachments/assets/881f56c3-c588-4d64-a5cc-cbeb00310d10)

---

This query helps you monitor **failed logon attempts** and **identify potential security risks** based on the geographical location of the source IP. Here’s a breakdown 🌐.
---

### **Your KQL Query**  

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;
```


1. **GeoIP Watchlist** 🌍:  
   `let GeoIPDB_FULL = _GetWatchlist("geoip");`  
   This loads a geolocation database to map IP addresses to location details like country, city, latitude, and longitude.

2. **Filtering Failed Logins** ❌:  
   - **`DeviceLogonEvents`**: This table contains the logon data for devices.
   - **`where ActionType == "LogonFailed"`** 🛑: Filters the data to only include failed logon attempts.

3. **Sorting Events** ⏳:  
   - **`order by TimeGenerated desc`** 🕒: Sorts the events by the most recent time of occurrence.

4. **GeoIP Enrichment** 🌍🔍:  
   - **`evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)`**: This function enriches the failed logon events by looking up the geographic location of the **RemoteIP** (the IP from which the logon attempt originated).

5. **Summarizing Data** 🔢:  
   - **`summarize LoginAttempts = count()`** 🔢: Counts the number of failed login attempts, grouped by the following fields:
     - **RemoteIP** 🌐: The source IP address of the failed login attempt.
     - **City** 🏙️: The city associated with the IP address.
     - **Country** 🌎: The country associated with the IP address.
     - **`friendly_location`** 🏷️: A combined label of city and country for easier readability (e.g., "London (UK)").
     - **Latitude** 📍 and **Longitude** 🌍: Geographical coordinates of the IP.

### Final Output:
This query provides a detailed view of **failed logon attempts**, including:
- **Remote IP** 🌐: The IP address that attempted to log in.
- **City & Country** 🏙️🌍: The city and country of the source IP.
- **Latitude & Longitude** 📍🌍: The geographical coordinates.
- **Login Attempts** 🔢: The number of failed login attempts for each source IP.
- **Friendly Location** 🏷️: A clear, combined label of city and country.

### Why It's Useful:
- **Security Insights** 🛡️: Helps detect and track failed login attempts and identify potential threats based on location.
- **Geographical Context** 🌍: Adds location details to each failed logon, helping to identify if there's unusual activity originating from specific countries or cities.
- **Proactive Measures** ⚠️: Enables you to take proactive security measures based on location-based anomalies, such as blocking certain regions or investigating suspicious patterns.
---

**Conclusion: Why CEOs and Non-Tech Leaders Like KQL Maps**  

KQL Maps turn complex data into easy-to-understand visuals 📊, helping CEOs and non-tech leaders spot security risks quickly 🚨. With location-based insights 🌍, they can make informed decisions 💡 without needing technical expertise, ensuring better protection for the company 🛡️. Simple, actionable, and effective! ✅
