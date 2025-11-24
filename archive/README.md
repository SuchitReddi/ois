**OIS - OSINT IOC Scanner**
OIS is a powershell script that takes multiple Indicators of Compromise (URI, Domain, IP, Hash) and looks them up in multiple Open Source sites.
This script will provide the neatly arranged result links in terminal. Works better when API keys are provided wherever needed.

1) Analysts can give their IOCs (Domain, IP, URL, Hash). The IOC type will be auto-validated by the script.
2) Maximum of 4 IOCs are recommended to limit excessive resource consumption. If more than four are given, a confirmation to proceed will be displayed.
3) The delimiters that can be used between two IOCs are: Space ( ), OR operator ( OR )( or ), and Comma (,).
4) The links for results will be displayed in terminal for analysts to copy paste as references.
5) After the process is done, the script asks again for IOCs until terminated manually.
6) The config.json file and urlscan.ps1 file can be placed anywhere in C:\Users\YOUR USERNAME HERE\Desktop\ois or C:\Users\YOUR USERNAME HERE\Desktop\ois\ois*.
7) If you have URLScan account, you can use the API to get a live screenshot for the URL. You will be prompted to choose if you want to use it or not in the beginning. If you want to change the choice later, you can edit it from e.
