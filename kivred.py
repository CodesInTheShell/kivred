###############################################################################################
#                                                                                             #
#    Kivred is a software to fetch threat intelligence data from feeds on a taxxi server.     #
#                                                                                             #
#    The author(s) is not liable for any damages arising from the use of this software and    #
#    is not giving any kind of guarantee that it works properly for the intended purpose.     #
#                                                                                             #
#    Anyone from anywhere can contribute to improve this software.                            #
#                                                                                             #
###############################################################################################


from threading import Thread # Implement this for the run button to avoid a (Not Responding) window.

from tkinter import *
from tkinter import messagebox, ttk
import requests
import random
from bs4 import BeautifulSoup

class MainGUI:

    def __init__(self, master):

        master.title("Kivred - Cyber Threat Intelligence")
        master.grid_rowconfigure(1, weight=1)
        master.grid_columnconfigure(1, weight=0)
        master.geometry("1210x600+20+20")

        #=====================================================VARIABLES========================================

        self.varDiscoUrl = StringVar()
        self.varFeedName = StringVar()
        self.varUserName = StringVar()
        self.varPassword = StringVar()
        self.varFrom = StringVar()
        self.varTo = StringVar()
        self.varStatus = StringVar()
        self.indicators = []
        self.observables = []
        self.ttps = []
        self.rawOutput = ""

        # ================================================== MENU ==============================================

        mainMenu = Menu(master)
        master.config(menu=mainMenu)
        fileMenu = Menu(mainMenu)
        mainMenu.add_cascade(label="File", menu=fileMenu)
        # fileMenu.add_command(label="New", command=self.eventTester)
        # fileMenu.add_separator()
        fileMenu.add_command(label="Exit", command=master.destroy)

        aboutMenu = Menu(mainMenu)
        mainMenu.add_cascade(label="About", menu=aboutMenu)
        aboutMenu.add_command(label="About this software", command=self.eventAbout)

        helpMenu = Menu(mainMenu)
        mainMenu.add_cascade(label="Help", menu=helpMenu)
        helpMenu.add_command(label="How to", command=self.eventHelp)

        #==================================FRAMES============================================

        logoFrame = Frame(master, bd=8, relief="raised")
        logoFrame.grid(row=0, column=0, sticky=N + E+W)

        setupFrame = Frame(master, bd=8, relief="raised", pady=5)
        setupFrame.grid(row=1, column=0, sticky=N+E+W+S)

        frameResult = Frame(master, bd=8, relief="raised")
        frameResult.grid(row=0, column=1, rowspan=3, sticky=N + W + E+S)

        statusFrame = Frame(master, bd=8, relief="raised")
        statusFrame.grid(row=2, column=0, sticky=N + W + E + S)

        # ==================================== LOGO HEADER ====================================================

        iconLabel = Label(logoFrame, text="K", bg="red", font=('arial', 50, 'bold'))
        iconLabel.grid(row=0, column=0)
        logoLabel = Label(logoFrame, text="Kivred - Cyber Threat Intelligence", bg="yellow", font=('arial', 20, 'bold'), pady=24)
        logoLabel.grid(row=0, column=1)

        # ===================================== SET UP FRAME ====================================================

        discoveryLabel = Label(setupFrame, text="Discovery URL:")
        discoveryLabel.grid(row=0, column=0, sticky=E, pady=7, padx=2)
        discoveryEntry = Entry(setupFrame, width=50, textvariable=self.varDiscoUrl)
        discoveryEntry.grid(row=0, column=1, sticky=W, pady=7, padx=2, columnspan=2)

        feedLabel = Label(setupFrame, text="Feed Name:")
        feedLabel.grid(row=1, column=0, sticky=E, pady=7, padx=2)
        feedEntry = Entry(setupFrame, width=30, textvariable=self.varFeedName)
        feedEntry.grid(row=1, column=1, sticky=W, pady=7, padx=5, columnspan=2)

        userLabel = Label(setupFrame, text="User Name:")
        userLabel.grid(row=2, column=0, sticky=E, pady=7, padx=2)
        userEntry = Entry(setupFrame, textvariable=self.varUserName)
        userEntry.grid(row=2, column=1, sticky=W, pady=7, padx=2, columnspan=2)

        passLabel = Label(setupFrame, text="Password:")
        passLabel.grid(row=3, column=0, sticky=E, pady=7, padx=2)
        passEntry = Entry(setupFrame, show='*', textvariable=self.varPassword)
        passEntry.grid(row=3, column=1, sticky=W, pady=7, padx=2, columnspan=2)

        fromLabel = Label(setupFrame, text="From:")
        fromLabel.grid(row=4, column=0, sticky=E, pady=7, padx=2)
        fromEntry = Entry(setupFrame, textvariable=self.varFrom)
        fromEntry.grid(row=4, column=1, sticky=W, pady=7, padx=2)

        toLabel = Label(setupFrame, text="To:")
        toLabel.grid(row=5, column=0, sticky=E, pady=7, padx=2)
        toEntry = Entry(setupFrame, textvariable=self.varTo)
        toEntry.grid(row=5, column=1, sticky=W, pady=7, padx=2)

        labelExampleFrom = Label(setupFrame, text="YYYY-M-D")
        labelExampleFrom.grid(row=4, column=2, sticky=W)
        labelExampleTo = Label(setupFrame, text="e.i    2016-8-20")
        labelExampleTo.grid(row=5, column=2, sticky=W)

        runButton = Button(setupFrame, text="Run", bd=3, command=self.eventRun, width=5, highlightcolor='green')
        runButton.grid(row=6, column=0, columnspan=3)

        # =========================================== RESULTS FRAME ==============================================

        frameResultTop = Frame(frameResult, bd=8, relief="raised")
        frameResultTop.grid(row=0, column=0, columnspan=2, sticky=N + W + E)

        frameResultSelection = Frame(frameResult, bd=8, relief="raised")

        frameResultSelection.grid(row=1, column=0, columnspan=2, sticky=N + W + E)
        frameResultOutput = Frame(frameResult, bd=8, relief="raised", width=40, height=200)
        frameResultOutput.grid(row=2, column=0, sticky=N + E + S+W)

        # ================================RESULTS WIDGETS==========================================================
        labelFeednameResults = Label(frameResultTop, text="Results",
                                          font=('helvetica', 15, 'bold'))
        labelFeednameResults.grid(row=0, column=0)

        labelSelect = Label(frameResultSelection, text="Select:            ", font=('helvetica', 12, 'bold'))
        labelSelect.grid(row=0, column=0, sticky=N + W + E)

        self.textOutput = Text(frameResultOutput, wrap=NONE)
        self.textOutput.grid(row=0, column=0, sticky=N+S+E+W)

        self.yscrollbarResult = Scrollbar(frameResult, cursor="arrow", width=20,
                                          command=self.textOutput.yview)
        self.yscrollbarResult.grid(row=2, column=1, sticky=N + S)
        self.xscrollbarResult = Scrollbar(frameResult, cursor="arrow", width=20,
                                          command=self.textOutput.xview,
                                          orient=HORIZONTAL)
        self.xscrollbarResult.grid(row=3, column=0, columnspan=2, sticky=E + W)

        self.textOutput.configure(yscrollcommand=self.yscrollbarResult.set)
        self.textOutput.configure(xscrollcommand=self.xscrollbarResult.set)

        buttonIndicator = Button(frameResultSelection, text="Indicators", activebackground="black",
                                 activeforeground='grey', padx=10, pady=15, command=self.eventIndicatorButton).grid(
            row=0, column=1, sticky=N + W + E, pady=2, padx=20)
        buttonObservables = Button(frameResultSelection, text="Observables", activebackground="black",
                                   activeforeground='grey', padx=10, pady=15, command=self.eventObservableButton).grid(
            row=0, column=2, sticky=N + W + E, pady=2, padx=20)
        buttonTtps = Button(frameResultSelection, text="TTPs", activebackground="black",
                            activeforeground='grey', padx=10, pady=15, command=self.eventTtpsButton).grid(row=0,
                                                                                                          column=3,
                                                                                                          sticky=N + W + E,
                                                                                                          pady=2,
                                                                                                          padx=20
                                                                                                          )
        buttonRaw = Button(frameResultSelection, text="Raw", activebackground="black",
                            activeforeground='grey', padx=10, pady=15, command=self.eventRaw).grid(row=0,
                                                                                                          column=4,
                                                                                                          sticky=N + W + E,
                                                                                                          pady=2,
                                                                                                          padx=20
                                                                                                          )

        # =========================================== STATUS FRAME ==============================================
        self.varStatus.set("Status: Not running")

        statusLabel = Label(statusFrame, textvariable=self.varStatus)
        statusLabel.grid(row=0, column=0, sticky=N+W+E)

    def eventTester(self):
        messagebox.showinfo('Title', 'It Works')

    def eventHelp(self):
        messagebox.showinfo('Help', """This product is tested to fetch data from hailataxii.

        Discovery URL: http://hailataxii.com/taxii-discovery-service
        
        Username: guest
        Password: guest
        
        Available feeds:
            guest.Abuse_ch
            guest.CyberCrime_Tracker
            guest.EmergingThreats_rules
            guest.Lehigh_edu
            guest.MalwareDomainList_Hostlist
            guest.blutmagie_de_torExits
            guest.dataForLast_7daysOnly
            guest.dshield_BlockList
            guest.phishtank_com
        
        More information can be found in there website.
        
        NOTES:
        
        When receiving a chunk size error on your request, maybe it is due to a large volume of data. 
        You may need to shorten the from and to stamp. A length of one day can give you a huge amount of result.
        
        When nothing is shown on Indicators, Observables and TTPs, you may want to check the raw output for issue.""")

    def eventAbout(self):
        messagebox.showinfo('About', """This software serves as a taxii client that can be use to fetch stix data from a taxii server.

        TAXII - Trusted Automated eXchange of Indicator Information. A free and open transport mechanism that standardizes
        the automated exchange of cyber threat information.
        
        STIX - Structured Threat Information Expression. is a language for describing cyber threat information
        in a standardized and structured manner to enable the exchange of cyber threat intelligence (CTI).
        
        Indicator – contains a pattern that can be used to detect suspicious or malicious cyber activity.
        
        Observed Data – conveys information observed on a system or network (e.g., an IP address).
        
        TTPs - Tactics, Techniques, and Procedures. (e.i., Malware, Attack Pattern)
        
        References and more information can be found on the following:
        https://www.oasis-open.org/
        https://oasis-open.github.io/cti-documentation/""")

    def eventRaw(self):
        self.textOutput.delete(1.0, END)
        try:
            self.textOutput.insert(END, self.rawOutput)
        except Exception:
            pass

    def eventIndicatorButton(self):
        self.textOutput.delete(1.0, END)
        for indicator in self.indicators:
            try:
                self.textOutput.insert(END, "Indicator ID: \n\t" + indicator.Indicator["id"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Title: \t" + indicator.Title.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Type: \t" + indicator.Type.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Description: \t" + indicator.Description.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Observable: \n\t" + indicator.Observable["idref"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Indicated TTP: \n\t" + indicator.Indicated_TTP.TTP["idref"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Confidence: \t" + indicator.Confidence.Value.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Producer: \t" + indicator.Producer.Identity.Name.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Produce Time: \t" + indicator.Produced_Time.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Type: \t" + indicator.find('Hashes').Hash.Type.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Value: \t" + indicator.find('Hashes').Hash.Simple_Hash_Value.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "___________________________________________________________________" + "\n")
            except Exception:
                pass

    def eventObservableButton(self):
        self.textOutput.delete(1.0, END)
        for observable in self.observables:
            try:
                self.textOutput.insert(END, "Observable ID: \n\t" + observable.Observable["id"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Title: \t" + observable.Title.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Description: \t" + observable.Description.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Object ID: \n\t" + observable.Object["id"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Timestamp Label: \t" + observable.Timestamp_Label.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Type: \t" + observable.find('Hashes').Hash.Type.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Value: \t" + observable.find('Hashes').Hash.Simple_Hash_Value.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "___________________________________________________________________"+ "\n")
            except Exception:
                pass

    def eventTtpsButton(self):
        self.textOutput.delete(1.0, END)
        for ttp in self.ttps:
            try:
                self.textOutput.insert(END, "TTP ID: \n\t" + ttp.TTP["id"] + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Title: \t\t" + ttp.Title.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Behavior: \n\t" + ttp.find('Behavior').contents[1].name + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Type: " + ttp.find('Behavior').Type.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Type: \t" + ttp.find('Hashes').Hash.Type.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "Hash Value: \t" + ttp.find('Hashes').Hash.Simple_Hash_Value.string + "\n")
            except Exception:
                pass
            try:
                self.textOutput.insert(END, "__________________________________________________________________"+ "\n")
            except Exception:
                pass

    def eventRun(self):
        #=================================GET ALL ENTRIES======================================================
        self.varStatus.set("Select on Indicators, Observables and TTPs button to see results")

        discoUrl = self.varDiscoUrl.get().strip()
        feedName = self.varFeedName.get().strip()
        userName = self.varUserName.get().strip()
        password = self.varPassword.get().strip()
        tempfrom = self.varFrom.get().strip()
        to = self.varTo.get().strip()

        headers = {'Content-Type': 'application/xml',
                   'User-Agent': 'Kivred - TAXII Client Applicatiion',
                   'Accept': 'application/xml',
                   'X-TAXII-Accept': 'urn:taxii.mitre.org:message:xml:1.1',
                   'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
                   'X-TAXII-Protocol': 'urn.taxii.mitre.org:protocol:https:1.0'}

        msgID = str(random.randint(111111, 9999999999))

        args = {'feed_name': feedName, 'msg_ID': msgID, 'begin_Stamp': tempfrom + "T00:00:00Z", 'end_Stamp': to + "T12:00:00Z"}

        initxmldata = """<?xml version='1.0' encoding='utf-8'?>
        <taxii_11:Poll_Request
            xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
            message_id="{msg_ID}"
            collection_name="{feed_name}">""".format(**args)

        initfrom = """
            <taxii_11:Exclusive_Begin_Timestamp>{begin_Stamp}</taxii_11:Exclusive_Begin_Timestamp>
            """.format(**args)

        initto = """
            <taxii_11:Inclusive_End_Timestamp>{end_Stamp}</taxii_11:Inclusive_End_Timestamp>
            """.format(**args)

        inittailxml = """
            <taxii_11:Poll_Parameters allow_asynch="false">
                <taxii_11:Response_Type>FULL</taxii_11:Response_Type>
            </taxii_11:Poll_Parameters>
        </taxii_11:Poll_Request>
        """.format(**args)

        if tempfrom:
            initxmldata += initfrom
        if to:
            initxmldata += initto

        xmldata = initxmldata + inittailxml

        try:
            r = requests.post(discoUrl, auth=(userName, password), headers=headers, data=xmldata)
        except Exception as e:
            messagebox.showinfo('Error', e)

        soup = BeautifulSoup(r.content, features="xml")
        self.rawOutput = soup.prettify()

        self.indicators = soup.find_all('Indicators')
        self.observables = soup.find_all('Observables')
        self.ttps = soup.find_all('TTPs')

        #Initially select the indicator results
        self.eventIndicatorButton()


        # ================================================ START OF THE PROGRAM ==========================================
root = Tk()
gui = MainGUI(root)

root.mainloop()

