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

# Concept Review
### *Which attacks were easiest to execute? Which were the most difficult?*
IDOR and User Enumeration were by far the fastest and least technically demanding. CSRF was painful. Required knowledge of the XSS vulnerability on green and a great deal of troubleshooting (mostly banging my head against a wall).
### *What is a good rule of thumb which would prevent accidentally username enumeration vulnerabilities like the one created here?*
Ensuring that returned page results or messages for both valid/existing users and for invalid users are the same. This can be accomplished with software tests that perform a diff of the results between the failed invalid user logon and the failed valid one. 
### *Since you should be somewhat familiar with the CMS and how it was coded, can you think of another resource which could be made vulnerable to an Insecure Direct Object Reference? What code could be removed which would expose it? (Hint: It was also the answer to the first bonus objective to the Weekly Assignment for week 3.)*
Based on my understanding of the question and assignment reference, the backend database would be vulnerable if we stick to the definition that IDOR is unauthenticated access to a resource that should require authorization. The piece of code that would prevent this related to week 3 is input validation, or whitelisting characters and sanitizing input.
###  *Many SQL Injections use OR as part of the injected code. (For example: ' OR 1=1 --'.) Could AND work just as well in place of OR? (For example: ' AND 1=1 --'.) Why or why not?*
Although useful in its own right, the AND would not substitue for an OR. The reason relates to the intended logic of the SQL statement with an OR 1=1 (which is intended to always return TRUE regardless of the other value) and using an AND. The AND adds an additional condition that must be met. For example, if you know the state of one parameter as TRUE, you can test another parameter for being TRUE/FALSE through the use of the AND. If that new parameter is FALSE the entire statement will return false. The AND is useful in blind SQLi beacuse of this indirect answer that doesn't rely on listed output.
### *A stored XSS attack requires patience because it could be stored for months before being triggered. Because of this, what important ingredient would an attacker most likely include in a stored XSS attack script?*
The element I can think of is a domain that will still resolve to an attacker's site even if that site has moved, or an active site that the script points to for callback or file downloads. A rod still connected to the line and hook as an analogy.
### *Imagine that one of your classmates is an authorized admin for the site's CMS and you are not. How would you get them to visit the self-submitting, hidden form page you created in Objective #5 (CSRF)?*
A small bit of social engineering would take care of that. Perhaps a comment that you heard someone posted a feedback comment that was scathing/harmful to the authorized admin's reputation or something that is known to bring them worry. Essentially create enough curiosity or concern to cause them to personally log in look at the feedback.
### *Compare session hijacking and session fixation. Which attack do you think is easier for an attacker to execute? Why? One of them is much easier to defend against than the other. Which one and why?*
Session hijacking is when an attacker takes the identifier of a legitimate session started by an authorized user and uses it for themselves. Session fixation is when an attacker starts a connection and then sets or provides that session to an unsuspecting user so that the user can add the authentication/authorization piece through a login but the session is still under control or known by the attacker. Session hijacking appears to be easier to execute as improperly secured cookies and XSS vulnerabilities allow session info to be gathered by an attacker. Session fixation requires more social engineering involvement but the defenses against it are simpler as the greatest fix is to regenerate the session identifier after authentication. Also, ensuring session ids are only set via cookies is another good defense. Session hijacking is more complex with multiple equally vulnerable points that must be defended or considered. 
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

