        _____           __
       /#####\         /##\              __
      /##__ ##|   ____ |__|             |##|
     | ##  \ #|  /####| __  ________  __|##|__
     | ##  | #| /##/__ | #|| ##__###||_ ####_/
     | ##  | #||######|| #|| #|  \##|  | ##|
     | ##  | #| \____#|| #|| #|  | #|  | ##|__
     |  #####//#######|| #|| #|  | #|  | ####/
      \_____/ |______/ |__||__/  |__/   \___/
     ________
     |_####_/  _____     ______
       | #|   /#####\   /######|
       | #|  |## __##| /##____/
       | #|  |##|  |#|| #|
      /####\ | ######||  ######|
     |______| \_____/  \______/
        _____
       /#####\
      /##__###|  _______  ______   _______   _______   _______  ________
     |##|  \__/ /######| /######| /#######| /#######| /##__## ||##___ ##|
     |##\____  /##_____/ |____|#|| ##__###|| ##__###||##|__|#/ |##|  \__/
      \____##\| ##        /#__##|| ##  \##|| ##  \##||###___/  |##|
      _____\##| ##       /#|__|#|| ##  |##|| ##  |##||##|_____ |##|
     |########|  ######|| ######|| ##  |##|| ##  |##||########\|##|
      \______/ \_______/\_______||__/  |__||__/  |__/ \_______||__/

OSINT IOC Scanner (OIS) By Suchit

Welcome, Sherlock! The game is on!

Installation:
- Just place the executable anywhere you want and double click to run.
- The first time you run the exe, a configuration file will be created. Keep it in the same location as the exe.

NOTE:
- If the exe crashes, place the bundled "crash error catcher.bat" in the same location and run it to get the crash error.

Usage:
- You can edit the configuration by giving input "e".
- To get the maximum output from the tool, API keys are required. 
--> URLScan API
You need to provide URLScan API key to get better URL search results.
If you don't have an account, create one at "https://urlscan.io/user/signup"
If you already have an account, get the API key here "https://urlscan.io/user/profile/"
Click on the New API key button to create an API key.
--> Virus Total API
You need to provide Virus Total API key to submit and pull results.
If you don't have an account, create one at "https://www.virustotal.com/gui/join-us"
If you already have an account, get the API key from the profile icon on the top right corner in Virus Total.

Overview:
1) Analysts can give their IOCs (Domain, IP, URL, Hash). The IOC type will be auto-validated by the script. Defanged IOCs are also processed.
2) Maximum of 4 IOCs are recommended to limit excessive resource consumption if you opt for opening results in browser. If more than four are given, a confirmation to proceed will be displayed.
3) The delimiters that can be used between two IOCs are: Space ( ), OR operator ( OR )( or ), and Comma (,).
4) The links for results will be displayed in terminal for analysts to copy paste as references.
5) After the process is done, the script asks again for IOCs until terminated manually.
6) The executable can be run from anywhere, but the config file created needs to be in the same directory.
7) If you submit Virus Total API Key, you can get many details directly in console. IOCs will be submitted to VT for reanalyzing when the script is run.
8) If you have URLScan account, you can use the API to get a live screenshot for the URL. You will be prompted to choose if you want to use it or not in the beginning. If you want to change the choice later, you can edit it from e.

Known Issues:
--> IOCs can't be seperated by new line character as powershell works differently in those cases.
--> When user selects clear screen, it doesn't clear the whole history which can be seen by scrolling up. But it does clear up the window.