## **KQL-Map-Azure-Authentication-Success**

## **Why KQL Maps Are Essential for CEOs and Business Leaders** 🌍📊

A KQL map transforms complex data into clear, actionable visuals, making it easier to spot trends, manage risks, and make informed decisions.  

- **Spot Trends Quickly**: See where activity is happening globally, from customer logins to potential risks.  
- **Strengthen Security**: Identify unusual activity in real time to stay ahead of threats.  
- **Simplify Data**: Turn overwhelming data into easy-to-understand visuals for your leadership team.  
- **Act Proactively**: Get real-time insights to respond faster to opportunities and challenges.  

Think of it as your business’s GPS for navigating data smarter and faster. 🚀

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
