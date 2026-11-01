# fenris-task

# Setting-UP Local agent

Local AI Agents using openClaw and ollama. The 'openclaw.json' is splited in 3 subparts as 'agentSetups_*' containg all the configs and partailly in powershell while agent setup.

To setup openclaw and ollama on clean machine use the Power shell file, first setup ollama and then openclaw. 

1.  Ollama
2.  docker network
3.  openclaw
    - setup-configurations complete i.e. ports, models download, etc
4.  configurations
    - model configurations, agents congfigurations

After setting up ollama and openclaw use the give flow to setup and config the agents. 

Powershell -> agentSetup (log-analyst + re-viewer then co-ordinator ) -> agentupdates _> failoversetup -> security-audit -> Demoruns