#!/usr/bin/env python3


class Gmail():
    '''
    Change recipients in get_recipients to control who the email is delivered to,
    add google app password to get_api_key and email account name to get_account_name.
    Blair 20180305
    '''

    def get_recipients(self):
        recipients = ["DL-ITBCyberSecurity@det.qld.gov.au"]
        #recipients = ["opsec.infomailer@gmail.com", "Adam.LEE@qed.qld.gov.au",
        #              "Adam.HARDEN@qed.qld.gov.au", "Blair.JAMES@qed.qld.gov.au"]
        return recipients

    def get_api_key(self):
        key = "kswtrnhibriwjbdq"
        return key

    def get_email_account(self):
        account = "opsec.infomailer@gmail.com"
        return account

    def sendFile(self, subject, file):
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            with open(str(file), "r") as filetxt:
                msgtext = MIMEText(filetxt.read(), "plain")
                to = "Alerts"
                recipients = self.get_recipients()
                msg = MIMEMultipart()
                msg['To'] = to
                msg['From'] = "Alerts"
                msg['Subject'] = ' %s ' % str(subject)
                msg.attach(msgtext)
                filetxt.close()
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(str(self.get_email_account()), str(self.get_api_key()))  #Google App password for login method
            server.sendmail(str(self.get_email_account()), recipients, msg.as_string())
            server.quit()
            print("Gmail sendFile completed successfully.\n")
            return True

        except Exception as e:
            mess = "Error! - det_Gmail.sendFile() through an exception " + str(e)
            print(mess)
            self.sendText(mess, mess)
            return False

    def sendText(self, subject, message):
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            msgtext = MIMEText(message, "plain")
            to = "Alerts"
            recipients = self.get_recipients()
            msg = MIMEMultipart()
            msg['To'] = to
            msg['From'] = "Alerts"
            msg['Subject'] = ' %s ' % str(subject)
            msg.attach(msgtext)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(str(self.get_email_account()), str(self.get_api_key())) #Google App password for login method
            server.sendmail(str(self.get_email_account()), recipients, msg.as_string())
            server.quit()
            print("Gmail sendText completed successfully.\n")
            return True

        except Exception as e:
            mess = "Error! - det_Gmail.sendText() through an exception " + str(e)
            print(mess)
            self.sendText(mess, mess)
            return False

def main():
    gm = Gmail()

if __name__ == '__main__':
    main()