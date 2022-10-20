# Email Notification Template
Dear **$developer**,

We are a team of researchers from the **$affiliation**, studying the GDPR (EU General Data Protection Regulation) consent for sharing users' personal data with third-party data controllers (use the data for their own purposes) in mobile apps. We are reaching out to you because of a potential GDPR violation in your app(s).

*This email is a part of an academic research project. We do not sell any products or services.*

Under GDPR[1], an app is required to obtain consent from users situated in the EU for sharing users' personal data with third-party data controllers. Based on our analysis, your app shares some user personal data with such third-party services (e.g., ads), and it has implemented a consent notice for such data sharing. However, in our automated tests, your app shares data without any given consent, or even after rejecting that consent/opting out, your app seemingly still shared data with third-party data controllers.

We have prepared a detailed report on the analysis methodology, the data being sent out, the parties involved, and all other details. You can access this through our (password-protected) Web interface at **$web_url** (please do not publish this URL as it is personalized for your app). 

Note that we are not threatening legal action or plan to involve regulators, or offer a conclusive legal assessment or consultancy. We aim to enable developers to address the issues before other parties might take any legal actions. Since we are also trying to understand the reasons for GDPR compliance issues of mobile apps in the wild, it would be immensely helpful to provide us with feedback regarding your app(s). 

- Were you aware that personal data -- based on the GDPR -- (i.e., **$sent_data**) is being collected and transmitted when you include third-party SDK(s) into your apps? 
- Are you aware of the GDPR consent requirements? For example, that the consent will not be considered "free" if the user is unable to refuse or withdraw their consent. 
- What type of support (e.g., documentation or automated tools) would benefit you to address such issues? 

Please contact us if you have further questions or wish not to receive further communication. We will diligently follow the request.

Best regards, **$researchers**

Disclaimer: This study is part of a research project of the **$affiliation**. The collected information will be used for scientific purposes only. Your responses are pseudonymous. We do NOT collect any personal information, publicize or perform any actions against your apps, and your company.

[1] General Data Protection Regulation. 2016. Regulation (EU) 2016/679 of the European Parliament and of the Council of 27 April 2016 on the protection of natural persons with regard to the processing of personal data and on the free movement of such data, and repealing Directive 95/46.
