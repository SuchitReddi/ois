Installation:
- Just place the executable anywhere you want and double click to run. You can add it to taskbar for better access.
- The first time you run the exe, a configuration file will be created. Keep it in the same location as the exe.
- You will be prompted different choices, which can be edited later by giving input “e”.
- Choose to use Virus Total and URLScan API and follow the instructions to obtain the API keys and submit them. This will provide a lot more information for each IOC. 

TROUBLESHOOTING:
If a terminal window opens and closes immediately, run the included batch file. It will show you the error causing the crash, giving you a chance to debug.

Usage:
You can edit the configuration by giving input "e". The options available for editing:
1) You can change the IOC limit. 
2) You can decide if you want to open the result links in browser or not. If yes, the results for each IOC will open in a separate browser window. 
But the URLScan results will be opened in the last window for all IOCs. 
(If you opted to open the results in browser and the limit is too great, system could lag.)
3) You can change the default browser the result links are opened in.
4) You can choose if you want to use APIs (Virus Total and URLScan for now).
5) Analysts can submit multiple IOCs (Domain, IP, URL, Hash) at once. IOC type will be auto validated. Defanged IOCs can also be given.
6) The delimiters that can be used between two IOCs are: Space ( ), OR operator ( OR )( or ), and Comma (,).
7) The executable can be run from anywhere, the config file created needs to be in the same directory.

Additional Information:
- You can click on any link in terminal while holding “Ctrl” to open it in browser.
- Every time you submit a valid IOC to the script, it will be sent to Virus Total to get an updated analysis, given you provided the API key. IOCs never seen on VT before will be submitted too.
- If Virus Total API Key is provided, you can get many details directly in console.
- If URLScan API key is provided, you can get a live screenshot for the URL.
- If the last analysis date is too old, you can submit the IOC after some time and you can see the updated results from your recent submission. (Hashes usually take longer than other IOCs.)
- When submitting an IOC to URLScan, the script sets visibility as “Private”.
- API Keys you submit are encrypted using Windows DPAPI and not stored in plain text in the config file. This security feature probably won’t work on non-windows devices. 


--> URLScan API
You need to provide URLScan API key to get better URL search results.
If you don't have an account, create one at (https://urlscan.io/user/signup)
If you already have an account, get the API key here (https://urlscan.io/user/profile/)
Click on “New API key” button to create an API key. Copy the key by hovering over it.
Change the settings to “Default Scan Visibility” as “Private” and then “Enforce”. 
The script takes care of it by submitting all API requests with Private visibility, but it’s better to be safe than sorry.

--> Virus Total API
You need to provide Virus Total API key to submit and pull results.
If you don't have an account, create one at (https://www.virustotal.com).
Analysts are usually provided an enterprise premium account, you can get the API key at (https://www.virustotal.com/gui/my-apikey).


Known Issues:
--> When user selects clear screen, it doesn't clear the whole history which can be seen by scrolling up. But it does clear up the window.