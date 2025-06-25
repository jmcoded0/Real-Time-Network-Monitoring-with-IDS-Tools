# 🚀 **My Personal Odyssey: Building a Network Monitoring & Intrusion Detection Lab**

Hey everyone! Buckle up, because this project is my deep dive into the fascinating, often chaotic, world of **network security and threat hunting**. After pouring my efforts into setting up my Splunk log analysis lab – which was an absolute game-changer for understanding system events – I hit a crucial realization: logs tell a story, but they don't always show the *entire* picture. To truly defend, you need to see the conversations happening *on the wires* themselves. That's why I embarked on this new journey: to build my very own Network Monitoring and Intrusion Detection System (IDS) lab.

This isn't just about following a guide; it's about pushing my boundaries, understanding attacks from a network perspective, and getting hands-on with the tools that security professionals use every single day. I'm building an isolated ecosystem right inside VirtualBox, where I can safely let loose and observe both friendly and, more importantly, *unfriendly* network traffic.

---

## **My "Why": Expanding My Cybersecurity Vision**

My drive for this project comes from a desire to gain a truly holistic view of security. With Splunk, I learned to interpret system activities and correlate events. Now, I want to layer on the **network dimension**. I'm setting this lab up to:

* **Gain Unparalleled Network Visibility:** Forget just glancing at connection logs. I want to see the actual packets, understand the protocols, and track conversations in real-time. This is about knowing *who's talking to whom, how, and why*.
* **Master the Art of Intrusion Detection:** It's one thing to read about IDS; it's another to deploy a powerful tool like Suricata, write rules, and see it alert on a simulated attack you just launched. This is where I'm learning to identify the tell-tale signs of malicious activity on the network itself.
* **Generate High-Fidelity Network Intelligence:** Beyond basic alerts, I'm integrating Zeek. This tool is a beast! It transforms raw packet data into rich, structured logs about every network conversation – HTTP requests, DNS queries, file transfers, and so much more. This granular data is invaluable for deep network forensics and threat hunting.
* **Build a Complete SIEM Picture:** The ultimate goal is to funnel all this new network data (Suricata alerts and Zeek logs) right back into my existing Splunk Enterprise instance. This integration is key to creating a truly powerful Security Information and Event Management (SIEM) solution, allowing me to correlate network anomalies with system events for a comprehensive view of my lab's security posture.

This project is truly valuable to me because it's forging a deeper understanding of cyber defense, from the raw packet level all the way up to centralized analysis. It’s practical, challenging, and directly applicable to real-world cybersecurity roles.

---

## **My Lab's Core Components: The Team Behind the Magic**

To bring this network monitoring dream to life, I'm relying on a carefully selected set of tools and virtual machines:

* **My Kali Linux VM (The Attacker & The Vigilant Eye):** This machine is pulling double duty. On one hand, it's my go-to for simulating various network attacks (like scans and exploit attempts) against my vulnerable target. On the other, and perhaps more crucially, it's transforming into my primary network monitoring station. Both Suricata and Zeek will be running here, sniffing traffic and generating security insights. And, of course, my Splunk Enterprise instance is still happily running on Kali, acting as the central collection point for all the network intelligence.

* **Metasploitable2 VM (The Unsuspecting Target):** Every good security lab needs a willing victim! Metasploitable2 is a Linux virtual machine specifically designed with known, exploitable vulnerabilities. It's perfect for me to safely practice my attack techniques against, and more importantly, it generates a ton of "interesting" (read: suspicious) network traffic that my IDS and monitoring tools will pick up. It's a fantastic, controlled environment for learning.

* **VirtualBox (My Isolation Chamber):** My trusty virtualization hypervisor, VirtualBox, is essential. It allows me to create this entire isolated network lab, keeping my experimental attacks and vulnerable machines safely contained. This ensures I can learn and experiment without any risk to my main computer or home network.

* **Suricata (My Network Sentinel - IDS/IPS):** This powerful open-source tool is my front-line defense. I'll configure Suricata in Intrusion Detection System (IDS) mode. It's like having a highly trained guard dog constantly sniffing the network packets, looking for signatures of known attacks, policy violations, and suspicious behavior. When it finds something, it generates an alert – a crucial piece of information for my Splunk instance.

* **Zeek (My Network Forensic Investigator):** More than just an IDS, Zeek (formerly known as Bro IDS) is a network security monitoring framework. While Suricata focuses on "alerts," Zeek is all about generating rich, highly detailed logs about *every* network conversation. Think connection logs, HTTP logs, DNS queries, SSL/TLS handshake data, even file transfers – all captured and beautifully organized into human-readable logs. This granular data is invaluable for deep network forensics and threat hunting.

* **Splunk Enterprise & Universal Forwarder (My Unified Intelligence Platform):** This is where it all comes together! My existing Splunk Enterprise instance on Kali will act as the central brain. I'll configure my Splunk Universal Forwarder (which is already on Kali) to pick up all the alerts from Suricata and the comprehensive logs from Zeek. Shipping this data to Splunk means I can correlate network events with my existing system logs, visualize patterns, build dashboards, and truly understand the full scope of any activity in my lab.
