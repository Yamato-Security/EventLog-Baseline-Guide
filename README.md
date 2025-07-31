# About EventLog-Baseline-Guide
A comprehensive Streamlit application for comparing and analyzing Windows Event Log audit settings across different security baseline guides.

## Live Demo
[https://yamato-security-eventlog-baseline-guide-streamlit-app-gwlyjo.streamlit.app/](https://yamato-security-eventlog-baseline-guide-streamlit-app-gwlyjo.streamlit.app/)

## Architecture
![Screenshot](img/06.png)

## Screenshot
![Screenshot](img/01.png)

![Screenshot](img/02.png)

![Screenshot](img/03.png)

![Screenshot](img/04.png)

![Screenshot](img/05.png)

## Features

### Windows Event Log Audit Settings Baseline Guide Comparison
Compare audit settings across multiple authoritative sources:
- **Windows Default**: Microsoft's default configuration
- **YamatoSecurity**: Community-driven security configurations
- **Australian Signals Directorate**: Government security recommendations
- **Microsoft Server**: Server-specific recommendations
- **Microsoft Client**: Client-specific recommendations

### Key Metrics
- **Audit Settings Analysis**: Detailed breakdown of recommended vs default settings
- **Log File Size Recommendations**: Optimal log retention settings
- **Sigma Rule Statistics**: Impact analysis on detection rule effectiveness
- **Service and Category Breakdown**: Granular analysis by Windows services and categories

## Color-Coded Interface

The application uses an intuitive color-coding system:
- **🟡 Yellow**: Changes required from default settings
- **🟢 Pale Green**: Default settings are acceptable
- **⚪ Light Gray**: No auditing required or no recommendations available

## Key Insights

The tool helps answer critical questions:
- Which audit settings need to be changed from defaults?
- How do different baseline guides compare?
- What's the impact on detection rule effectiveness?
- Which Windows services are most affected by configuration changes?

## How to use(locally)
```
git clone https://github.com/Yamato-Security/EventLog-Baseline-Guide.git
cd EventLog-Baseline-Guide
pip install -r requirements.txt
streamlit run streamlit_app.py 
```
## Other Windows Event Log Audit Settings Related Resources
* [A Data-Driven Approach to Windows Advanced Audit Policy – What to Enable and Why](https://www.splunk.com/en_us/blog/security/windows-audit-policy-guide.html)
* [Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
* [Configure audit policies for Windows event logs](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection)
* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)
* [Windows event logging and forwarding](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)
* [mdecrevoisier/Windows-auditing-baseline](https://github.com/mdecrevoisier/Windows-auditing-baseline)
* [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding/tree/master/group-policy-objects)

## Contributing

We would love any form of contribution. Pull requests, rule creation and sample evtx logs are the best but feature requests, notifying us of bugs, etc... are also very welcome.
At the least, if you like our tool then please give us a star on GitHub and show your support!

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

*This tool is designed to help security professionals make informed decisions about Windows event log configuration based on established security baselines and their impact on detection rule effectiveness.*
