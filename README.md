# Tarrask
Tarrask: Hafnium's persistence via hidden scheduled task

# Research
Today I decided to start paying my Cyber Security community debt and contribute into Forensics and Threat Hunting space.
I am going to share possibly an unusual way of hunting for hidden Windows 10 scheduled tasks in memory, allowing to detect tasks having no registry nor disk artifacts. 

![image](https://github.com/wit0k/tarrask/blob/main/task_in_memory.jpg)

Feel free to look at my quick research [#Tarrask - Deep dive - Hidden Scheduled Task](https://github.com/wit0k/tarrask/blob/main/Tarrask_Persistence_Deep_Dive.pdf), it consist of following topics:

* Scheduled Task Artifacts
* Hiding Scheduled Task
* Detecting Hidden Scheduled Tasks
* Analyzing Hidden Scheduled Tasks
* Tools ([TaskHunter](https://github.com/wit0k/tarrask/blob/main/TaskHunter.ps1) & [GetTasks](https://github.com/wit0k/tarrask/blob/main/GetTasks.py))
* Key Takeaways
 
P.S The tools are quickly written PoC scripts, only tested few Windows 10 systems. Additionally, you would spot that Microsoft Windows itself is using few hidden tasks by default. 



