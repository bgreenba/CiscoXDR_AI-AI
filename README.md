# CiscoXDR_AI-AI
Cisco XDR AI Assisted Investigations (DEVNET-2387 at Cisco Live US 2025)

## What does it do?
This project allows you to add functionality to XDR that will 
- provide the capability for you to enter your own custom reference links to observables in the pivot menu (stage 1)
- provide the ability to have those lookups done for you and the results parsed and displayed in the pivot menu without you having to click on them (stage 2)
- provide the ability, when responding to an incident, to send those parsed reference lookup results for all observables in the incident, to a generative AI engine for analysis and guidance (the workflow)

## Included files: 
|file|description|
|---|---|
|AIAI-moduleType.json|The ModuleType specification to use either server below in XDR| 
|app-stage1-pivotrefs.py|A simple reference server that provides links for observable lookups|
|references.py|The list of reference pivots and details that are used by stage1 above|
|app-stage2-prefetchers.py|A reference server that creates the lookup link and then fetches, parses, and returns the content|
|AIAI - [Analyze Incident Observables Metadata] Workflow.json|The workflow that takes the lookup results from stage 2 and creates the worklog entry then submits them to the AI engine|

## Deployment Instructions
1. Deploy the web application of your choice (or both) on a webserver. These were developed on and for Apache2 running [mod_wsgi](https://pypi.org/project/mod-wsgi/) and the [Flask](https://flask.palletsprojects.com/en/stable/) framework.  YMMV on anytihng else.
2. Upload the AIAI-moduleType.json file contents as a POST to the https://visibility.amp.cisco.com/iroh/iroh-int/module-type API endpoint (or regional equivalent) to put the module in your private catalog.
3. Find the integration in your catalog and click the + button to open the installation and configuration page
4. Follow the instructions on that page; basically input the URL at which you installed the code in step 1 and click 'save'.
5. If the healthcheck passes, you are good to go! Go do an investigation or view an incident and see the new options in the pivot menu on observables. IF it failed, troubleshoot and restart :)
6. In XDR Automate, import the workflow for use in Incident Response. 

##Contributors:
- Matthew Franks
- Christopher Van Der Made
- Brandon Macer
- Matt Vander Horst
- Ben Greenbaum
