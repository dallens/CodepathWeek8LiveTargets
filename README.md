# CodepathWeek8LiveTargets
# Project 8 - Pentesting Live Targets

Time spent: **20** hours spent in total

> Objective: Find, analyze, recreate, and document **six vulnerabilities** affecting a live site.

## Pentesting Report

### 1. Wordpress Plugin Reflex Gallery Arbitrary File Upload and Remote Code Execution Exploit
  - [ ] Summary:
		1. A vulnerability in the Reflex Gallery Plugin allows remote file upload, which can provide for remote code execuion with a carefully crafted payload.  
    - Vulnerability types: Remote Code Execution
    - Tested in version: 3.1.3
    - Fixed in version: 3.1.4
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_Reflex.gif)
  - [ ] Steps to recreate: 
    - 1. Using the Metasploit Framework, use the exploit/unix/webapp/wp_reflexgallery_file_upload module.
    - 2. Set the remote host to the Wordpress instance.
    - 3. [Link Rapid7](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_reflexgallery_file_upload)
  - [ ] Affected source code:
    - [Link WordpressVulndb](https://wpvulndb.com/vulnerabilities/7867)
### 2. WordPress Commit Diff for Milestone 6 
  - [ ] Summary: 
		1. Completion of the Milestone 7 Lab Step.
    - Vulnerability types: N/A
    - Tested in version: 3.1.3
    - Fixed in version: 3.1.4 
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_ReflexChangesDiff.gif)
  - [ ] Steps to recreate: 
    - [ ] Affected source code:
    - [Link Diff](https://plugins.trac.wordpress.org/changeset?old_path=%2Freflex-gallery&old=1114986&new_path=%2Freflex-gallery&new=1114986&sfp_email=&sfph_mail=#file0)
    - [Link Plugin](https://plugins.trac.wordpress.org/log/reflex-gallery/)
### 3. Olimometer SQLi
  - [ ] Summary: 
		1. The Olimometer plugin has a vulnerable parameter (olimometer_id) which allows SQL injection and database exploitation.
    - Vulnerability types: SQLi
    - Tested in version: 2.56
    - Fixed in version: (unfixed)
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_Olimometer.gif)
  - [ ] Steps to recreate: 
    - 1. Based on the exploit listed at [Link Exploit](https://packetstormsecurity.com/files/139921/WordPress-Olimometer-2.56-SQL-Injection.html)
    - 2. sqlmap -u http://wpdistillery.vm/wp-content/plugins/olimometer/thermometer.php?olimometer_id=1 -p "olimometer_id" -a --dbs --threads=5 --random-agent --no-cast
  - [ ] Affected source code:
    - [Link ](https://wordpress.org/plugins/olimometer/)
### 1. Username Enumeration:
  - [ ] Summary: 
		1. The green site is vulnerable to username enumeration via the selective bolding of the error message.
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_UsernameEnumeration.gif)
### 2. Insecure Direct Object Reference:
  - [ ] Summary: 
		1. The red site is vulnerable to IDOR via the id parameter of the URL for the saleperson lookup.
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_IDOR.gif)
### 3. SQL Injection:
  - [ ] Summary: 
		1. The blue site's id parameter in the URL string for the salesperson lookup is vulnerable to SQLi.
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_BlueSQLiUsers.gif)
### 4. Cross-Site Scripting:
  - [ ] Summary: 
		1. User submitted XSS data in the feedback form will display as XSS in the admin portal of the green site.
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_XSS.gif)
### 5. Cross-Site Request Forgery:
  - [ ] Summary: 
		1. The red site was vulnerable to CSRF. However, the green site's vulnerability to XSS was needed in order to cause the form to be submitted to the red site by the admin logged into the green site.
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_RedCSRF.gif)
### 6. Session Hijacking/Fixation
  - [ ] Summary: 
		1. Sessions may be hijacked on the blue site. 
  - [ ] GIF Walkthrough: ![](https://github.com/dallens/CodepathWeek8LiveTargets/blob/master/W8_BlueSessionHijack.gif)
## Assets

List any additional assets, such as scripts or files

## Resources

- [WordPress Source Browser](https://core.trac.wordpress.org/browser/)
- [WordPress Developer Reference](https://developer.wordpress.org/reference/)

GIFs created with [LiceCap](http://www.cockos.com/licecap/).

## Notes

Describe any challenges encountered while doing the work

## License

    Copyright [yyyy] [name of copyright owner]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

