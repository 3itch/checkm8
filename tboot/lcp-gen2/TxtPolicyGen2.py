#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

#  TXT Policy Generator Tool

# using print() built-in function, disable print statement
from __future__ import print_function

#
# wxPython is not part of the standard Python distribution and has to be downloaded and installed separately.
# Tell the user that wxPython is required but has not been found
#
try:
  import wx
except ImportError:
  raise ImportError, "Please download the appropriate version of wxPython from www.wxpython.org"

try:
  import os
except ImportError:
  raise ImportError, "import OS failed"

from defines import DEFINES
from pdef import PDEF
pdef = PDEF()

from util import UTILS
utilities = UTILS()

from build import Build
build = Build()

from list import LIST
list = LIST()

from tools import TOOLS
tools = TOOLS()

# Note:  using cPickle's default text format [vs. binary] since the former is portable across Python versions
try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version

import datetime
import sys

filename = "NewPlatform.pdef"
dirname  = os.getcwd()



# builds can be initiated from clicking the build button or
# specifying a batch build on the command line
BUILD_BATCH = 0             # same a BUILD_BUTTON but initi8ated from the command line
BUILD_BUTTON = 1            # build both the NV_POLICY (.pol) and POLICY DATA file (.dat)
BUILD_NV_POLICY_ONLY = 2    # build only the NV POLICY file (.pol)
BUILD_POLICY_DATA_ONLY = 3  # build only the POLICY DATA file (.dat)
 #
 # MyFrame class contains:
 #  File and Help menu pull downs
 #  [Menu Tool bar]
 #  BUILD button
 #  Policy Panel
 #    PS/PO Policy type checkbox
 #    ...
 #
class MyFrame(wx.Frame):

  def __init__(self, parent, id, title):
    # First, call the base class' __init__ method to create the frame
    wx.Frame.__init__(self, parent, id, title, size=(820, 450))

    global dirname, filename

    self.StatusBar = self.CreateStatusBar()     # Add a Statusbar in the bottom of the window
    self.createMenuBar()                        # Add a menu bar with File & Help menus
    #self.createToolBar()                        # Add a tool bar
    #TODO: TBD: $$$$ to purchase toolbar icons if toolbar is to be enabled
    self.createPolicyPanel()                    # add initial policy panel

    # CLI syntax:
    # 'TxtPolGen2.py -open MySystem.pdef -build' does a batch build of MySystem.pdef
    # 'TxtPolGen2.py -hash file.bin startOffset offsetSize  hashAlgorithm'
    #
    hashImageSyntax = "'TxtPolGen2 -hash file.bin startOffset offsetSize  hashAlgorithm'\n"
    if(len(sys.argv) == 1):
      # Invoke GUI
      pass
    elif((sys.argv[1] == '-open') or (sys.argv[1] == '-hash')):           # CLI cmd
      filepath = os.path.abspath(os.path.normpath(sys.argv[2]))
      dirname = os.path.dirname(filepath)
      filename = os.path.basename(filepath)

      if(sys.argv[1] == '-open'):
        msg = "Batch build of %s" % (filename)
        if(self.verifyPdefFile() == True):
          status = True
          print("len(sys.argv) = %d, args=%s" % (len(sys.argv), sys.argv)) # DBGDBG
          if(len(sys.argv) > 3):
            if(sys.argv[3] == '-build'):
              print("Starting %s ..." % (msg))
              self.batchBuild()
              print("%s complete" % (msg))
              sys.exit()             # exit if batch build succeeded
            else:
              status = False
          else:
            status = False

          if(status == False):
            error = " failed. Expected a '-build' option"
            print("%s %s" % (msg, error))
            sys.exit()             # exit
        else:
          error = " failed. Invalid pdef file."
          print("%s %s" % (msg, error))
          sys.exit()             # exit
      elif(sys.argv[1] == '-hash'):
        if(len(sys.argv) < 5):
          # invalid -hash syntax
          print("%s" % (hashImageSyntax))
        else:
          tools.hashImage(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        sys.exit()             # exit
      else:
        print("%s" % (hashImageSyntax))
        sys.exit()

    else:                 # invalid CLI syntax, using GUI, print syntax help
      help = "\n'TxtPolGen2' - invoke GUI\n'TxtPolGen2 -open File.pdef -build' - performs a batch build of File.pdef\n"
      print("%s%s" % (help, hashImageSyntax))
      sys.exit()

  # verify the .pdef file to be opened for a batch build
  def verifyPdefFile(self):
    """verifyPdefFile - verify the file in argv[2] exists and has a .pdef extention"""

    if(len(sys.argv) > 2):
      # chk for a .pdef ext
      base, ext, = filename.rsplit('.', 1)
      if(ext == "pdef"):
        # chk the file exists by opening it
        try:
          f = open(os.path.join(dirname, filename), 'r')
        except:
          print("Error opening file %s" % (filename))
          return(False)   # open failed so nothing to close

        f.close()

      else:
        return False      # invalid extention

    return True   # ok

  #
  # Create the menu bar with file & help menus.
  #
  def createMenuBar( self ):
    """createMenuBar - create the Menu Bar"""
    FileMenu = wx.Menu()
    HelpMenu = wx.Menu()
    BuildMenu = wx.Menu()
    ToolMenu = wx.Menu()

    FileMenuNew   = FileMenu.Append(wx.ID_NEW,    "&New",     " Create a new Policy")
    FileMenuOpen  = FileMenu.Append(wx.ID_OPEN,   "&Open",    " Open a saved PDEF file")
    FileMenuSave  = FileMenu.Append(wx.ID_SAVE,   "&Save",    " Save Policy to a PDEF file")
    FileMenuSaveAs= FileMenu.Append(wx.ID_SAVEAS, "&Save As", " Save Policy to a PDEF file")
    FileMenuPrint = FileMenu.Append(wx.ID_PRINT,  "&Print",   " Save Policy to a printable text file")
    FileMenuClose = FileMenu.Append(wx.ID_EXIT,   "&Close",   " Close the Policy and exit")

    # Creating the menubar.
    MenuBar = wx.MenuBar()
    MenuBar.Append(FileMenu, "&File")     # Adding the "FileMenu" to the MenuBar

    BuildMenuBuildNvPolicy          = BuildMenu.Append(wx.ID_ANY, "&Build just NV Policy File",   "Build only the NV Policy")
    BuildMenuBuildPolicyDataStruct  = BuildMenu.Append(wx.ID_ANY, "&Build just Policy Data File", "Build only the Policy Data Struct")
    BuildMenuBuildBoth              = BuildMenu.Append(wx.ID_ANY, "&Build Policy (both files)",   "Build the full Policy")
    MenuBar.Append(BuildMenu, "&Build")

    #ToolMenuHashFile                = ToolMenu.Append(wx.ID_ANY, "&Hash a file",   "Create a hash from the specified file")
    #ToolMenuInsertPolicy            = ToolMenu.Append(wx.ID_ANY, "&Insert policy", "Insert a policy into an image per its FIT7 record")
    #MenuBar.Append(ToolMenu, "&Tools")      # Adding the "ToolMenu" to the MenuBar

    HelpMenuToolInfo  = HelpMenu.Append(wx.ID_ABOUT, "&Tool Info",       " Display information about this tool")
    HelpMenuLicense   = HelpMenu.Append(wx.ID_ANY,   "&License",         " Display the license")
    HelpMenuKeyGen    = HelpMenu.Append(wx.ID_ANY,   "&Key Generation",  " How to generatekeys with OpenSSL")
    HelpMenuBatch     = HelpMenu.Append(wx.ID_ANY,   "Batch Build Help", "Build from the command line")
    HelpMenuHash      = HelpMenu.Append(wx.ID_ANY,   "Hash Image Help",  "Hash an image from the command line")
    HelpMenuGuide     = HelpMenu.Append(wx.ID_ANY,   "&Guide",           " Open the User Guide")
    HelpMenuTutorial  = HelpMenu.Append(wx.ID_ANY,   "&Tutorial",        " Open the Tutorial")
    MenuBar.Append(HelpMenu, "&Help")      # Adding the "HelpMenu" to the MenuBar

    self.SetMenuBar(MenuBar)              # Adding the MenuBar to the Frame content.

    #
    # Menu events
    #
    self.Bind(wx.EVT_MENU, self.onNew,      FileMenuNew)
    self.Bind(wx.EVT_MENU, self.onOpen,     FileMenuOpen)
    self.Bind(wx.EVT_MENU, self.onSave,     FileMenuSave)
    self.Bind(wx.EVT_MENU, self.onSaveAs,   FileMenuSaveAs)
    self.Bind(wx.EVT_MENU, self.onPrint,    FileMenuPrint)
    self.Bind(wx.EVT_MENU, self.onExit,     FileMenuClose)

    self.Bind(wx.EVT_MENU, self.onAbout,        HelpMenuToolInfo)
    self.Bind(wx.EVT_MENU, self.onLicense,      HelpMenuLicense)
    self.Bind(wx.EVT_MENU, self.onKeyGen,       HelpMenuKeyGen)
    self.Bind(wx.EVT_MENU, self.batchBuildHelp, HelpMenuBatch)
    self.Bind(wx.EVT_MENU, self.hashImageHelp,  HelpMenuHash)
    self.Bind(wx.EVT_MENU, self.onGuide,        HelpMenuGuide)
    self.Bind(wx.EVT_MENU, self.onTutorial,     HelpMenuTutorial)

    self.Bind(wx.EVT_MENU, self.onBuildButtonClick,      BuildMenuBuildBoth)
    self.Bind(wx.EVT_MENU, self.onBuildNvPolicy,         BuildMenuBuildNvPolicy)
    self.Bind(wx.EVT_MENU, self.onBuildPolicyDataStruct, BuildMenuBuildPolicyDataStruct)

    #self.Bind(wx.EVT_MENU, self.onHashFile,       ToolMenuHashFile)
    #self.Bind(wx.EVT_MENU, self.onInsertPolicy,   ToolMenuInsertPolicy)

  #
  # Create the ToolBar
  #
  def createToolBar( self ):
    """createToolBar - create the Tool Bar"""
    toolbar = self.CreateToolBar()
    for each in self.toolBarData():
      self.createSimpleTool( toolbar, *each )
    toolbar.AddSeparator()
    toolbar.Realize()

    #exitTool = ToolBar.AddLabelTool( wx.ID_ANY, 'Exit', wx.Bitmap('texit.png'))
    #ToolBar.Realize()
    #self.Bind(wx.EVT_TOOL, self.OnExit, ExitTool)

  def createSimpleTool( self, toolbar, label, filename, help, handler):
    """createSimpleTool - create a simple tool for the Tool Bar"""
    bmp = wx.Image( filename, wx.BITMAP_TYPE_BMP).ConvertToBitmap()
    tool = toolbar.AddSimpleTool( -1, bmp, label, help)
    #tool = toolbar.AddSimpleTool( -1, wx.NullBitmap, label, help)
    self.Bind( wx.EVT_MENU, handler, tool )

  def toolBarData( self ):
    #       label,                           filename,   help,                                   handler
    return(("New",                           "new.bmp",  "Create a new Policy",                  self.onNew),
           ("Open",                          "open.bmp", "Open a saved PDEF file",               self.onOpen),
           ("Save",                          "save.bmp", "Save Policy to a PDEF file",           self.onSave),
           ("Save as a printable text file", "save.bmp", "Save Policy to a printable text file", self.onPrint),
    #       ("Tool Info",                    "help.bmp", "Tool info",                            self.onAbout)
           )


  #
  # Create the Default Policy Panel
  #
  #   Policy Rules   Version        Control Options     Policy Type     Hash Alg
  #  [rnd chk box    text box       sq chkbox           rnd chk box     pulldown]
  #   --------------------------------------------------------------------------
  #     PS          Version    2.2  Allow NPW           LIST            SHA1
  #     PO          MinSINITVer  0  SINIT Cap...        ANY
  #
  #   Number of   View List     Add List    Delete List   ACM Revocation Limits   [text]
  #   Lists                                               BIOS      SINIT
  #  [text box    text box      button      button        text box  text box]
  #
  def createPolicyPanel( self ):
    """ createPolicyPanel - create the Policy Panel"""
    # Create a ScrolledWindow with a BoxSizer to contain every panel
    self.scrollableWindow = wx.ScrolledWindow(self, wx.ID_ANY, style=wx.TAB_TRAVERSAL)
    self.scrollableWindow.SetScrollbars(1, 1, 1, 1)
    self.scrollableWindow.SetScrollRate(10, 10)
    self.scrollableWindow.SetAutoLayout(1)
    self.scrollableWindowSizer = wx.BoxSizer(wx.VERTICAL)
    self.scrollableWindow.SetSizer(self.scrollableWindowSizer)

    # create the Policy Panel with a GridBagSizers
    self.policyPanel = wx.Panel(self.scrollableWindow, -1)
    self.policyPanelSizer = wx.GridBagSizer(hgap=5, vgap=5)
    self.policyPanel.SetSizer(self.policyPanelSizer)

    policyLabel = wx.StaticText(self.policyPanel, -1, "Policy")
    font18 = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    policyLabel.SetFont( font18 )
    self.policyPanelSizer.Add( policyLabel, pos=(1, 0))

    pdefFileLabel = wx.StaticText(self.policyPanel, label="PDEF File: ")
    self.policyPanelSizer.Add( pdefFileLabel, pos=(0,4))
    self.pdefFileName  = wx.TextCtrl( self.policyPanel, value='None', size=(140, -1))
    self.pdefFileName.Enable( False )                                          # Version cannot be modified
    self.policyPanelSizer.Add( self.pdefFileName,  pos=(0,7))

    #  PS/PO Policy Rules Radio Buttons   - PDEF.Rules
    self.psRadioButton = wx.RadioButton( self.policyPanel, -1, "PS Policy Rules", style=wx.RB_GROUP)
    self.poRadioButton = wx.RadioButton( self.policyPanel, -1, "PO Policy Rules")
    self.poRadioButton.SetValue( True )

    self.policyPanelSizer.Add( self.psRadioButton, pos=(2,0), span=(1,2))
    self.policyPanelSizer.Add( self.poRadioButton, pos=(3,0), span=(1,2))

    self.Bind(wx.EVT_RADIOBUTTON, self.onPolicyRulesRadioClick, self.psRadioButton)
    self.Bind(wx.EVT_RADIOBUTTON, self.onPolicyRulesRadioClick, self.poRadioButton)

    # Version text boxes: Version [PDEF.PolVersion] & Min SINIT Version [PDEF.SINITMinVersion]
    self.versionLabel = wx.StaticText(self.policyPanel, label="Version: ")
    self.policyPanelSizer.Add( self.versionLabel, pos=(1,3))
    supportedversions = sorted(DEFINES.SUPPORTED_LCP_VERSION.keys(), reverse=True)
    defaultversion = supportedversions[0]
    self.versionEdit = wx.ComboBox( self.policyPanel, size=(40, -1), value=defaultversion, choices=supportedversions, style=wx.CB_READONLY)
    #self.versionEdit.Enable( False )                                          # Version cannot be modified
    self.policyPanelSizer.Add( self.versionEdit,  pos=(1,4))
    self.Bind(wx.EVT_TEXT, self.onPolicyVersion, self.versionEdit)
    majorstring, minorstring = defaultversion.split('.')
    pdef.PolVersionMajor = int(majorstring)
    pdef.PolVersionMinor = int(minorstring)

    self.minSinitVersionLabel = wx.StaticText(self.policyPanel, label="Min SINIT Version: ")
    self.policyPanelSizer.Add(self.minSinitVersionLabel, pos=(2,3))
    minSinitVersion = pdef.SinitMinVersion                               # get current value
    self.minSinitVersionEdit  = wx.TextCtrl( self.policyPanel, value=str(minSinitVersion), size=(30, -1))
    self.policyPanelSizer.Add( self.minSinitVersionEdit,  pos=(2,4))
    self.Bind(wx.EVT_TEXT, self.onMinSinitVersion, self.minSinitVersionEdit)

    # Control Options - Checkboxes - PDEF.PolicyControl
    contolOptionsLabel = wx.StaticText(self.policyPanel, -1, "Control Options")
    font10 = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    contolOptionsLabel.SetFont( font10 )

    self.allowNPW = wx.CheckBox(self.policyPanel, label="Allow NPW")
    self.sinitCapabilites = wx.CheckBox(self.policyPanel, label="SINIT Capabilities in PCR17")
    self.auxDelete = wx.CheckBox(self.policyPanel, label="AUX Delete")
    self.auxDelete.Enable( False )

    self.forceOwnerPolicyValue = False
    self.forcePsPconfValue = True
    pdef.PolicyControl |= DEFINES.PolicyControlForceOwnerBitMask  # Initialize PolicyConrol with forcePsPconf bit set.
    self.forcePsOrPo = wx.CheckBox(self.policyPanel,  label="Force PS PCONF")     # inverse of Force Owner Policy
    self.forcePsOrPo.SetValue( self.forcePsPconfValue )                                    # defaults to checked => bit=0
    #self.forceOwnerPolicy = wx.CheckBox(self.policyPanel, label="Force Owner Policy")   # inverse of Force PS PCONFIG
    #self.forceOwnerPolicy.Hide()
    self.ignorePsStm = wx.CheckBox(self.policyPanel,  label="Ignore PS STM")
    self.ignorePsPconf = wx.CheckBox(self.policyPanel,  label="Ignore PS PCONF")
    self.ignorePsMle = wx.CheckBox(self.policyPanel,  label="Ignore PS MLE")

    self.Bind(wx.EVT_CHECKBOX, self.onNpwPolicyControl, self.allowNPW)
    self.Bind(wx.EVT_CHECKBOX, self.onPcr17PolicyControl, self.sinitCapabilites)
    self.Bind(wx.EVT_CHECKBOX, self.onForcePsOrPoPolicyControl, self.forcePsOrPo)
    #self.Bind(wx.EVT_CHECKBOX, self.onForceOwnerPolicyControl, self.forceOwnerPolicy)
    self.Bind(wx.EVT_CHECKBOX, self.onAuxDelete, self.auxDelete)
    self.Bind(wx.EVT_CHECKBOX, self.onIgnorePsStm, self.ignorePsStm)
    self.Bind(wx.EVT_CHECKBOX, self.onIignorePsPconf, self.ignorePsPconf)
    self.Bind(wx.EVT_CHECKBOX, self.onIgnorePsMle, self.ignorePsMle)

    self.policyPanelSizer.Add(contolOptionsLabel,    pos=(3,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.allowNPW,         pos=(4,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.sinitCapabilites, pos=(5,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.auxDelete,        pos=(6,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.forcePsOrPo,      pos=(7,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    #self.policyPanelSizer.Add(self.forceOwnerPolicy, pos=(7,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.ignorePsStm,      pos=(8,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.ignorePsPconf,    pos=(9,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.ignorePsMle,      pos=(10,7), span=(1,2), flag=wx.BOTTOM, border=5)

    # Hide ignoreXXX GUI if it's not LCP policy version 3.1
    if defaultversion == '3.1':
      self.showV31Gui(True)
    else:
      self.showV31Gui(False)

    # Policy Type Radios List: LIST, ANY - PDEF.PolicyType
    policyTypeLabel = wx.StaticText(self.policyPanel, -1, "Policy Type")
    policyTypeLabel.SetFont( font10 )

    self.listRadioButton = wx.RadioButton( self.policyPanel, -1, "LIST", style=wx.RB_GROUP)
    self.anyRadioButton = wx.RadioButton( self.policyPanel, -1, "ANY")
    self.anyRadioButton.SetValue(  True )
    self.selectedPolicyType = self.anyRadioButton

    self.Bind(wx.EVT_RADIOBUTTON, self.onPolicyTypeRadioClick, self.listRadioButton)
    self.Bind(wx.EVT_RADIOBUTTON, self.onPolicyTypeRadioClick, self.anyRadioButton)

    self.policyPanelSizer.Add(policyTypeLabel,       pos=(5,0), span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.listRadioButton,  pos=(7,0), span=(1,2), flag=wx.BOTTOM, border=5)
    self.policyPanelSizer.Add(self.anyRadioButton,   pos=(6,0), span=(1,2), flag=wx.BOTTOM, border=5)

    # Hash Alg combobox Control
    hashList = DEFINES.SUPPORTED_HASHES
    self.hashAlgLabel = wx.StaticText(self.policyPanel, label="Hash\nAlgorithm")
    self.hashAlgLabel.SetFont( font10 )
    self.policyPanelSizer.Add(self.hashAlgLabel, pos=(0,10))

    self.hashAlgEdit = wx.ComboBox( self.policyPanel, size=(75, -1), value="SHA256", choices=hashList, style=wx.CB_READONLY )
    self.hashAlgEdit.Enable( False )      # disabled since Policy Type: ANY is default
    self.policyPanelSizer.Add(self.hashAlgEdit, pos=(1,10))
    self.Bind(wx.EVT_TEXT, self.onHashAlg, self.hashAlgEdit)

    # Algorithm for Auto-Promotion
    self.algForApLabel = wx.StaticText(self.policyPanel, label="Algorithm for\nAuto-Promotion")
    self.algForApLabel.SetFont( font10 )
    self.policyPanelSizer.Add(self.algForApLabel, pos=(0,13))

    self.algForApEdit = wx.ComboBox( self.policyPanel, size=(75, -1), value="SHA256", choices=hashList, style=wx.CB_READONLY )
    self.algForApEdit.Enable( True )    # disabled since Policy Type: ANY is default
    self.policyPanelSizer.Add(self.algForApEdit, pos=(1,13))
    self.Bind(wx.EVT_TEXT, self.onAlgForAp, self.algForApEdit)

    # Algorithm Allowed for LCP
    self.algAllowedForLcpLabel = wx.StaticText(self.policyPanel, label="Algorithms Allowed for\nLaunch Control Policy")
    self.algAllowedForLcpLabel.SetFont( font10 )
    self.policyPanelSizer.Add(self.algAllowedForLcpLabel, pos=(2,10), span=(1,2))

    hashList = DEFINES.ALLOWED_HASHES
    self.algAllowedForLcpEdit = wx.CheckListBox( self.policyPanel, -1, size=wx.DefaultSize, choices=hashList, style=wx.LB_MULTIPLE)
    self.policyPanelSizer.Add(self.algAllowedForLcpEdit, pos=(3,10), span=(8,3))
    self.Bind(wx.EVT_CHECKLISTBOX, self.onAlgAllowedForLcp, self.algAllowedForLcpEdit)

    # Set the default value from PDEF structure
    checkedLCP = []
    for item in DEFINES.TPM_ALG_HASH_MASK.keys():
      if(pdef.LcpHashAlgMask & DEFINES.TPM_ALG_HASH_MASK[item]):
        checkedLCP.append(item)
    self.algAllowedForLcpEdit.SetCheckedStrings(checkedLCP)

    # Allowed Signature Schemes
    self.allowedSigSchemesLabel = wx.StaticText(self.policyPanel, label="Allowed Signature\nSchemes")
    self.allowedSigSchemesLabel.SetFont( font10 )
    self.policyPanelSizer.Add(self.allowedSigSchemesLabel, pos=(2,13))

    sigList = DEFINES.ALLOWED_SIGNATURE_SCHEMES
    self.allowedSigSchemesEdit = wx.CheckListBox( self.policyPanel, -1, size=wx.DefaultSize, choices=sigList, style=wx.LB_MULTIPLE)
    self.policyPanelSizer.Add(self.allowedSigSchemesEdit, pos=(3,13), span=(8,3))
    self.Bind(wx.EVT_CHECKLISTBOX, self.onAllowedSigSchemes, self.allowedSigSchemesEdit)

    checkedSign = []
    for item in DEFINES.TPM_ALG_SIGN_MASK.keys():
      if(pdef.LcpSignAlgMask & DEFINES.TPM_ALG_SIGN_MASK[item]):
        checkedSign.append(item)
    self.allowedSigSchemesEdit.SetCheckedStrings(checkedSign)

    # Number of Lists text box
    self.numOfListsLabel = wx.StaticText(self.policyPanel, label="Number of Lists")
    self.policyPanelSizer.Add( self.numOfListsLabel, pos=(8,3))
    self.numOfListsEdit  = wx.TextCtrl( self.policyPanel, value="", size=(30, -1))
    self.numOfListsLabel.Enable( False )
    self.numOfListsEdit.Enable( False )
    self.policyPanelSizer.Add( self.numOfListsEdit,  pos=(8,4))

    # View List text box
    self.viewListLabel = wx.StaticText(self.policyPanel, label="View List")
    self.policyPanelSizer.Add( self.viewListLabel, pos=(9,3))
    self.viewListEdit  = wx.TextCtrl( self.policyPanel, value="", size=(30, -1))
    self.viewListLabel.Enable( False )
    self.viewListEdit.Enable( False )
    self.policyPanelSizer.Add( self.viewListEdit,  pos=(9,4))
    self.Bind(wx.EVT_TEXT, self.onViewList, self.viewListEdit)

    # Add and Delete List buttons
    self.addListButton = wx.Button( self.policyPanel, -1, label="Add    List ", style=wx.BU_EXACTFIT)
    self.addListButton.Enable( False )
    self.policyPanelSizer.Add( self.addListButton, pos=(8, 0))
    self.Bind(wx.EVT_BUTTON, self.onAddListButtonClick, self.addListButton) # add event handler

    self.deleteListButton = wx.Button( self.policyPanel, -1, label="Delete List", style=wx.BU_EXACTFIT)
    self.deleteListButton.Enable( False )
    self.policyPanelSizer.Add( self.deleteListButton, pos=(9, 0))
    self.Bind(wx.EVT_BUTTON, self.onDeleteListButtonClick, self.deleteListButton) # add event handler

    # ACM Revocation Limits  static text [PDEF.MaxBiosMinVersion & PDEF.MaxSinitMinVersion ]
    self.acmRevLabel = wx.StaticText(self.policyPanel, -1, "ACM Revocation Limits")
    self.acmRevLabel.SetFont( font10 )
    self.policyPanelSizer.Add( self.acmRevLabel, pos=(3, 3), span=(1,4))

    # BIOS text box
    self.biosLabel = wx.StaticText(self.policyPanel, label="BIOS")
    self.policyPanelSizer.Add( self.biosLabel, pos=(4,3))
    value = pdef.MaxBiosMinVersion                                   # get current value
    self.biosEdit  = wx.TextCtrl( self.policyPanel, value=str(value), size=(30, -1))
    self.policyPanelSizer.Add( self.biosEdit,  pos=(4,4))
    self.Bind(wx.EVT_TEXT, self.onBiosRevLimit, self.biosEdit)

    # SINIT text box
    self.sinitLabel = wx.StaticText(self.policyPanel, label="SINIT")
    self.policyPanelSizer.Add( self.sinitLabel, pos=(5,3))
    value = pdef.MaxSinitMinVersion                                 # get current value
    self.sinitEdit  = wx.TextCtrl( self.policyPanel, value=str(value), size=(30, -1))
    self.policyPanelSizer.Add( self.sinitEdit,  pos=(5,4))
    self.Bind(wx.EVT_TEXT, self.onSinitRevLimit, self.sinitEdit)

    #self.policyPanelSizer.Add(policyGridSizer, 0, wx.ALL, 5)
    #policyHorizSizer.Add(policyGridSizer,  0, wx.ALL, 5)
    #self.policyPanelSizer.Add(policyHorizSizer, 0, wx.ALL, 5)
    #self.scrollableWindow.SetSizerAndFit(self.policyPanelSizer)
    self.scrollableWindowSizer.Add(self.policyPanel, 0, wx.ALL, 5)
    w,h = self.scrollableWindowSizer.GetMinSize()
    self.scrollableWindow.SetVirtualSize((w,h))
    self.scrollableWindow.Layout()

    self.StatusBar.SetStatusText( "FileTypeSignature = %s, DefCompany = %s, StructVersion = %s" %
      (pdef.FileTypeSignature, pdef.DefCompany, pdef.StructVersion))

  ############################
  # File Menu Event Handlers #
  ############################
  def onNew(self, event):
    """ onNew - Create a new PDEF file"""

    global pdef, list

    if(pdef.Modified == True):
      self.StatusBar.SetStatusText( "Save current PDEF file first?." )
      self.savePdefFile(title="Save current PDEF file?", name=filename)
      self.StatusBar.SetStatusText( "" )

    if(pdef.NumLists != 0):
      list.hideListPanel()
      w,h = self.scrollableWindowSizer.GetMinSize()
      self.scrollableWindow.SetVirtualSize((w,h))
      self.scrollableWindow.Layout()

    pdef = PDEF()
    list = LIST()
    self.PolListInfo = {'0':None, '1':None, '2':None, '3':None,
                        '4':None, '5':None, '6':None, '7':None }
    #self.setDefaultPdef()
    self.restorePanel()
    # Create a new PDEF project file with default settings.
    # The selected directory will be the working directory.
    self.savePdefFile(title="New PDEF project", name="NewPlatform.pdef")

  def onOpen(self, event):
    """ onOpen - Open an existing PDEF file"""
    global filename, dirname, pdef

    #self.dirname = ''   #  current owrking directory
    wildcard = "PDEF file (*.pdef)|*.pdef|" \
               "All Files (*.*)|*.*"
    dlg = wx.FileDialog(self, "Choose the PDEF file", dirname, "", wildcard, wx.FD_OPEN)

    if dlg.ShowModal() == wx.ID_OK:
        filename = dlg.GetFilename()
        dirname  = dlg.GetDirectory()
        pdef = PDEF()     # loadAndDisplayPdefFile use pickle to load the saved file, does it overwrite pdef entirely?
        self.pdefFileName.ChangeValue(filename)
        self.loadAndDisplayPdefFile()
        pdef.WorkingDirectory = dirname
    dlg.Destroy()

  #
  # If the PDEF has been modified, save it to specified name and return True
  # if not modified, return False
  #
  def savePdefFile(self, title, name):
    """ savePdefFile - perform Save or SaveAs"""

    global filename, dirname

    wildcard = "PDEF file (*.pdef)|*.pdef|" \
               "All Files (*.*)|*.*"
    dlg = wx.FileDialog(self, title, dirname, name, wildcard, wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT)

    if dlg.ShowModal() == wx.ID_OK:
      filename = dlg.GetFilename()
      dirname  = dlg.GetDirectory()
      pdef.Modified = False
      pdef.WorkingDirectory = dirname
      self.pdefFileName.ChangeValue(filename)
      self.writePdefFile()
      self.printPdefTextFile()
      if (self.listRadioButton.GetValue() == True ):
        self.enableDisableListWidgets( True )
      else:
        self.enableDisableListWidgets( False )
      # originally, filename had no extension so strip it off keeping the user supplied base name
      #filename, ext = filename.rsplit('.', 1)
      print("DEBUG TxtPolicyGen2: Working Directory = %s" %dirname)
    else:
      print("savePdefFile: user cancelled, PDEF not saved") # DBGDBG

    dlg.Destroy()
    #print("savePdefFile - done. filename=%s" % (filename))  # DBGDBG
    return True

  def confirmSavePdefFile(self, title, name):
    """ savePdefFile - perform Save or SaveAs"""

    dlg = wx.MessageDialog(self, name+" Exists.\nOverwrite existing file?", title, wx.OK|wx.CANCEL|wx.ICON_QUESTION)

    if dlg.ShowModal() == wx.ID_OK:
      pdef.Modified = False   # Want to save this status
      self.writePdefFile()
      self.printPdefTextFile()
      print("DEBUG TxtPolicyGen2: Working Directory = %s" %dirname)
    else:
      print("savePdefFile: user cancelled, PDEF not saved") # DBGDBG

    dlg.Destroy()
    return True

  def onSave(self, event):
    """ onSave - Save a file"""
    base = self.getBasePdefFile()
    if (self.pdefFileName.GetValue() == "None"):
      self.savePdefFile(title="Save PDEF File", name=base)
      return True
    else:
      self.confirmSavePdefFile(title="Confirm Overwrite", name=filename)
      return True

  def onSaveAs(self, event):
    """ onSaveAs - Save a file as ..."""
    base = self.getBasePdefFile()
    self.savePdefFile(title="Save PDEF File As", name=base)

  def onPrint(self, event):
    """ onPrint - save policy as a printable text file"""
    self.printPdefFile()

  def onExit(self,  event):
    """ onExit - close any open PDEF's and exit"""
    if(pdef.Modified == True):
      self.savePdefFile(title="Save Policy before exiting?", name=filename)

    self.Close(True)  # Close the frame.

  ############################
  # Help Menu Event Handlers #
  ############################
  def onAbout(self, event):
    """ onAbout - provide Help/About info"""
    # A message dialog box with an OK button.
    dlg = wx.MessageDialog( self, "TXT Policy Generator v%d, Release %s, Build date %s" %
                           (DEFINES.LCP_VERSION, DEFINES.TOOL_VERSION, DEFINES.BUILD_DATE),
                           "About TXT Policy Generator" )

    dlg.ShowModal() # Show dialog & wait for OK or Cancel
    dlg.Destroy() # finally destroy it when finished.

  def onLicense(self, event):
    """ onLicense - display the license"""

    license = 'Win LCP Generator License.pdf'
    self.openPdf(license)

  def openPdf(self, file):
    """openPdf - display the specified pdf file"""

    #import subprocess
    #from subprocess import CalledProcessError

    # make sure the file is present
    try:
      f = open(file, 'r')
    except:
      msg = "File %s not found"  % (file)
      self.StatusBar.SetStatusText("%s" % (msg))
      print("%s" % (msg))
      return

    f.close()

    self.StatusBar.SetStatusText( "Opening Acrobat reader to display file %s..."  % (file))

    # form the aboslute path to the pdf and pass that to acrobat
    try:
      if os.name == 'nt':
        #subprocess.check_call(['C:\Program Files (x86)\Adobe\Reader 10.0\Reader\AcroRd32.exe', os.path.join(os.getcwd(),file)])
        os.startfile(file)
      else:
        #subprocess.check_call(['evince', os.path.join(os.getcwd(),file)])
        os.system('xdg-open ' + file)
    except Exception as e:
      print(e.returncode)

    self.StatusBar.SetStatusText( "" )

  def onKeyGen(self, event):
    """ onKeyGen - Generating keys with OpenSSL"""

    dlg = wx.MessageDialog( self,
      "To create public and private keys with OpenSSL:\n   openssl genrsa -out PrivateKeyFile.pem [1024,2048,3072]\n   openssl rsa -pubout -in PrivateKeyFile.pem -out PublicKeyFile.pem\n",
      "Key Generation")
    dlg.ShowModal() # Show dialog & wait for OK or Cancel
    dlg.Destroy()   # finally destroy it when finished.

  def batchBuildHelp(self, event):
    """ batchBuildHelp - help for batch builds"""

    dlg = wx.MessageDialog( self,
      "To perform a build of a previously saved pdef file from the command line or a script:\ttxtPolGen2 -open MySystem.pdef -build\n",
      "Batch Build Help")
    dlg.ShowModal() # Show dialog & wait for OK or Cancel
    dlg.Destroy()   # finally destroy it when finished.

  def hashImageHelp(self, event):
    """ hashImageHelp - help for hashing image from cmd line"""

    dlg = wx.MessageDialog( self,
      "To hash an image from the command line or a script:\ttxtPolGen2 -hash image.bin startOffset offsetSize hashAlgorithm\nwhere 4=SHA1, 0xb=SHA256",
      "Hash Image Help")
    dlg.ShowModal() # Show dialog & wait for OK or Cancel
    dlg.Destroy()   # finally destroy it when finished.

  def onGuide(self, event):
    """ onGuide - Open the User Guide"""
    file = 'LCP2Gen User Guide.pdf'
    self.openPdf(file)

  def onTutorial(self, event):
    """ onTutorial - Open the Tutorial"""
    #TODO: NiceToHave: onTutorial - implement HelpMenu: Tutorial
    self.StatusBar.SetStatusText("No Tutorial yet.")

  #def onHashFile(self, event):
  #  """onHashFile - hash the specified file"""
  #  self.StatusBar.SetStatusText( "This feature is not implemented from GUI, please use command line." )
  #
  #  #from tools import TOOLS
  #  #tools = TOOLS()
  #  #
  #  #TODO:  For GUI, need to get the parameters:biosFileName, startOffset, offsetSize and hashAlg from the user
  #  #
  #  #tools.hashImage(biosFileName, startOffset, offsetSize, hashAlg)
  #
  #def onInsertPolicy(self, event):
  #  """onInsertPolicy - insert a policy into an image per the FIT type 7 record"""
  #  self.StatusBar.SetStatusText( "This feature is not implemented yet." )

  ########################
  ###GUI Event Handlers###
  ########################

  #
  # LIST or ANY Policy Type Radio buttons clicked
  #
  def onPolicyTypeRadioClick(self, event):
    """ onPolicyTypeRadioClick - LIST or ANY Policy Type radio button selected, enable /disable widgets """
    #self.StatusBar.SetStatusText( "You clicked a Policy Type Radio Button! id %i, LIST id= %i" % ( event.GetId(), self.listRadioButton.GetId() ) )
    #print("in onPolicyTypeRadioClick")      # DBGDBG

    #pdef.Modified = True
    if event.GetId() == self.listRadioButton.GetId() :
      # Policy Type: LIST selected, enable LIST widgets
      if(self.pdefFileName.GetValue() == "None"):
        # Force user to create a new empty .pdef file for project working directory.
        value = False
      else:
        value = True
      self.hashAlgEdit.Enable( True )       # enable Hash Algorithm ComboBox when switch from ANY to LIST
      pdef.PolicyType = DEFINES.LIST
      if(pdef.NumLists > 0):
        list.showListPanel()
    else :
      # Policy Type: ANY selected, disable LIST widgets & LIST panel
      value = False
      self.hashAlgEdit.Enable( False )      # disabled since Policy Type: ANY is default
      pdef.PolicyType = DEFINES.ANY
      list.hideListPanel()

    self.enableDisableListWidgets( value )
    policyTypeRadioSelected = event.GetEventObject()

  def setPsRulesMode(self):
    """ setPsRulesMode - set for PS rules"""
    # PS Policy Rules selected, enable forceOwnerPolicy
    #self.forceOwnerPolicy.Enable( True )
    #self.forcePsPconf.Enable( False )

    # Cannot place 2 widgets in the same location, so remove one
    self.forcePsOrPo.SetLabel("Force Owner Policy")
    self.forcePsOrPo.SetValue(self.forceOwnerPolicyValue)
    #self.forcePsPconf.Hide()
    #self.forceOwnerPolicy.Hide()
    #self.policyPanelSizer.Remove(self.forcePsPconf)     # remove both checkboxes and add one back to avoid error
    #self.policyPanelSizer.Remove(self.forceOwnerPolicy)
    #self.policyPanelSizer.CheckForIntersection(self.forceOwnerPolicy, excludeItem=self.forcePsPconf)
    #self.policyPanelSizer.Add(self.forceOwnerPolicy, pos=(7,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    #self.forceOwnerPolicy.Show()

    self.ignorePsStm.Enable( False )
    self.ignorePsPconf.Enable( False )
    self.ignorePsMle.Enable( False )    
    
    self.auxDelete.Enable( True )
    #self.acmRevLabel.Enable( False )
    self.biosEdit.Enable( False )
    self.sinitEdit.Enable( False )
    #self.biosLabel.Enable( False )
    #self.sinitLabel.Enable( False )
    self.policyPanelSizer.Layout()
    
    # update pdef.PolicyControl after switching to PS Policy Rule radio button.
    if(self.forcePsOrPo.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlForceOwnerBitMask
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlForceOwnerBitMask

    if(self.auxDelete.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlAUXDeletionControl
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlAUXDeletionControl
      
    # Clear Ignore_PS_xxx bits
    pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsStmBitMask
    pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsPconfBitMask
    pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsMleBitMask
      
    self.StatusBar.SetStatusText("PDEF.PolicyControl = 0x%x" % (pdef.PolicyControl) )

    # if current list has a PCONF element, disable its OverridePsPolicy checkbox
    #if((1 <= pdef.CurrentListView) and (pdef.CurrentListView <= pdef.NumLists)):
    #  list.enablePconfOverridePsPolicyCheckbox(False)

  def setPoRulesMode(self):
    """ setPoRulesMode - set for PO rules"""
    # PO Policy Rules selected, disable forceOwnerPolicy
    #self.forceOwnerPolicy.Enable( False )
    #self.forcePsPconf.Enable( True )
    
    # Cannot place 2 widgets in the same location, so destroy and recreate

    self.forcePsOrPo.SetLabel("Force PS PCONF")
    self.forcePsOrPo.SetValue(self.forcePsPconfValue)
    #self.forceOwnerPolicy.Hide()
    #self.forcePsPconf.Hide()
    #self.policyPanelSizer.Remove(self.forceOwnerPolicy)
    #self.policyPanelSizer.Remove(self.forcePsPconf)     # remove both checkboxes and add one back to avoid error
    #self.policyPanelSizer.CheckForIntersection(self.forcePsPconf, excludeItem=self.forceOwnerPolicy)
    #self.policyPanelSizer.Add(self.forcePsPconf,     pos=(7,7),  span=(1,2), flag=wx.BOTTOM, border=5)
    #self.forcePsPconf.Show()
    
    self.ignorePsStm.Enable( True )
    self.ignorePsPconf.Enable( True )
    self.ignorePsMle.Enable( True )

    self.auxDelete.Enable( False )
    #self.acmRevLabel.Enable( True )
    self.biosEdit.Enable( True )
    self.sinitEdit.Enable( True )
    #self.biosLabel.Enable( True )
    #self.sinitLabel.Enable( True )
    self.policyPanelSizer.Layout()
    
    # update pdef.PolicyControl after switching to PO Policy Rule radio button
    if(self.forcePsOrPo.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlForceOwnerBitMask
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlForceOwnerBitMask
      
    if(self.ignorePsStm.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlIgnorePsStmBitMask
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsStmBitMask
    
    if(self.ignorePsPconf.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlIgnorePsPconfBitMask
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsPconfBitMask
      
    if(self.ignorePsMle.GetValue() == 1):
      pdef.PolicyControl |= DEFINES.PolicyControlIgnorePsMleBitMask
    else:
      pdef.PolicyControl &= ~DEFINES.PolicyControlIgnorePsMleBitMask
      
    # clear AuxDelete bit
    pdef.PolicyControl &= ~DEFINES.PolicyControlAUXDeletionControl
    
    self.StatusBar.SetStatusText("PDEF.PolicyControl = 0x%x" % (pdef.PolicyControl) )

    # if current list has a PCONF element, enable its OverridePsPolicy checkbox
#    if((1 <= pdef.CurrentListView) and (pdef.CurrentListView <= pdef.NumLists)):
#      list.enablePconfOverridePsPolicyCheckbox(True)

  #
  # PS or PO Policy Rules Radio buttons clicked
  #
  def onPolicyRulesRadioClick(self, event):
    """  onPolicyRulesRadioClick - PS or PO Policy Rules Radio button selected, enable/disable widgets """
    #print("in onPolicyRulesRadioClick")      # DBGDBG

    pdef.Modified = True
    if event.GetId() == self.psRadioButton.GetId() :
      self.setPsRulesMode()
      pdef.Rules = DEFINES.PsRules

      # if the list panel has been created, and no Sbios panel exists, enable the Add SBIOS button
      if(pdef.NumLists > 0):
        currentListObject = pdef.getCurrentListObject()
        list.rebuildAddElementChoicesForPsRules()  # add SBIOS if they don't exist

        # Does all element has PS Policy override checkbox?
        # earlier code only enable/disable OverridePsPolicy for SBOS and MLE
        list.syncVersion(pdef.Rules)
        #for element in list.includedElements:
        #  element.enableDisableOverridePsPolicy(False)
    else :
      self.setPoRulesMode()
      pdef.Rules = DEFINES.PoRules

      # if the list panel has been created, remove the SBIOS entries
      if(pdef.NumLists > 0):
        currentListObject = pdef.getCurrentListObject()
        list.rebuildAddElementChoicesForPoRules()

        list.syncVersion(pdef.Rules)
        #for element in list.includedElements:
        #  element.enableDisableOverridePsPolicy(True)


  def onHashAlg(self, event):
    """onHashAlg - update pdef.HashAlg"""
    pdef.HashAlg  =  DEFINES.TPM_ALG_HASH[event.GetString()]
    #if(event.GetString() == "SHA1"):
    #  pdef.HashAlg  =  DEFINES.TPM_ALG_SHA1
    #elif(event.GetString() == "SHA256"):
    #  pdef.HashAlg  =  DEFINES.TPM_ALG_SHA256
    #elif(event.GetString() == "SHA384"):
    #  pdef.HashAlg  =  DEFINES.TPM_ALG_SHA384
    #elif(event.GetString() == "SHA512"):
    #  pdef.HashAlg  =  DEFINES.TPM_ALG_SHA512
    pdef.Modified = True
    self.StatusBar.SetStatusText( "HashAlg=%d" %(pdef.HashAlg))

  def onAlgForAp(self, event):
    """onAlgForAp - update algorithm for auto promotion"""

    pdef.AuxHashAlgMask  =  DEFINES.TPM_ALG_HASH_MASK[event.GetString()]
    #if(event.GetString() == "SHA1"):
    #  pdef.AuxHashAlgMask  =  DEFINES.TPM_ALG_HASH_MASK_SHA1
    #elif(event.GetString() == "SHA256"):
    #  pdef.AuxHashAlgMask  =  DEFINES.TPM_ALG_HASH_MASK_SHA256
    pdef.Modified = True
    self.StatusBar.SetStatusText( "AuxHashAlgMask=0x%X" %(pdef.AuxHashAlgMask))

  def onAlgAllowedForLcp(self, event):
    """onAlgAllowedForLcp - update algorithm allowed for launch control policy (pdef.LcpHashAlgMask)"""

    checkedList = self.algAllowedForLcpEdit.GetCheckedStrings()
    mask = 0
    for item in checkedList:
      mask = mask | DEFINES.TPM_ALG_HASH_MASK[item]

    pdef.LcpHashAlgMask = mask
    pdef.Modified = True
    #print("DEBUG onAlgAllowedForLcp: mask = 0x%08x" %mask)
    self.StatusBar.SetStatusText("LcpHashAlgMask=0x%X" %(pdef.LcpHashAlgMask))

  def onAllowedSigSchemes(self, event):
    """onAllowedSigSchemes - update allowed signature schemes (pdef.LcpSignAlgMask)"""

    checkedList = self.allowedSigSchemesEdit.GetCheckedStrings()
    mask = 0
    for item in checkedList:
      mask = mask | DEFINES.TPM_ALG_SIGN_MASK[item]

    pdef.LcpSignAlgMask = mask
    pdef.Modified = True
    self.StatusBar.SetStatusText("LcpSignAlgMask=0x%X" %(pdef.LcpSignAlgMask))
    #print("DEBUG onAllowedSigSchemes: mask = 0x%08x" %mask)

  #
  # BUILD Button clicked
  #
  # Update pdef.LastBuild[Date,Time]Stamp
  # if modified, Save .pdef [& .pdef.txt] use that base name for .dat, .pol & .txt
  # else prompt for a base name
  #
  # Generate a .dat [LCP_POLICY_DATA] which includes building the elements and hashing the signed and unsigned lists
  # Generate .pol and txt of the LCP_POLICY
  #
  def onBuildButtonClick(self, event):
    """ onBuildButtonClick - BUILD button clicked, build the current definition """
    status = self.build(BUILD_BUTTON)   # doing a build from a button click event
    if (status == True):
      dlg = wx.MessageDialog(self, "Build Completed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    else:
      dlg = wx.MessageDialog(self, "Build Failed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    currentList = pdef.getCurrentListObject()
    list.restoreListPanel(currentList) # Update revocation number

  def onBuildNvPolicy(self, event):
    """ onBuildNvPolicy - build just the NV Policy"""
    status = self.build(BUILD_NV_POLICY_ONLY)
    if (status == True):
      dlg = wx.MessageDialog(self, "Build Completed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    else:
      dlg = wx.MessageDialog(self, "Build Failed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    currentList = pdef.getCurrentListObject()
    list.restoreListPanel(currentList) # Update revocation number

  def onBuildPolicyDataStruct(self, event):
    """ onBuildPolicyDataStruct - build just the Policy Data Struct"""
    status = self.build(BUILD_POLICY_DATA_ONLY)
    if (status == True):
      dlg = wx.MessageDialog(self, "Build Completed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    else:
      dlg = wx.MessageDialog(self, "Build Failed", "Build Status", wx.OK|wx.ICON_INFORMATION)
      dlg.ShowModal()
      dlg.Destroy()
    currentList = pdef.getCurrentListObject()
    list.restoreListPanel(currentList) # Update revocation number

  # buildMode can be:
  #   BUILD_BATCH  if build initiated from cmd line:
  #         txtPolicyGen.py -open MySystem.pdef -build
  #   BUILD_BUTTON          - if build initiated by clicking the build button or build both build menu
  #   BUILD_NV_POLICY_ONLY  - if build initiated by clicking the 'build just NV Policy' build menu  (.pol)
  #   BUILD_POLICY_DATA_ONLY- if build initiated by clicking the 'build just POLICY DATA' build menu (.dat)
  #
  def build(self, buildMode):
    """build - perform a build"""

    global filename, dirname

    # update the build time and date stamps
    # Per TXT Policy Generator 5.3.1, clear the PDEF's Data Revocation Counters
    # if PolicyType = LIST, and at least 1 list, then update the list and pdef RevocationCounters
    # do all this now so it is in the  pdef and pdef.txt saved below
    self.updateLastBuildDateAndTimeStamps()
    pdef.DataRevocationCounters = [0,0,0,0,0,0,0,0]
    if(pdef.PolicyType == DEFINES.LIST):
      if(pdef.NumLists > 0):
        list.onBuildButtonClick(pdef)

    # don't need to save current pdef if doing a batch build
    if((buildMode == BUILD_BUTTON) or
       (buildMode == BUILD_NV_POLICY_ONLY) or
       (buildMode == BUILD_POLICY_DATA_ONLY)):
      # if needed save the current PDEF to base.pdef & base.pdef.txt
      # NOTE: in the saved PDEF's, the PolicyHash has not been calculated yet
      #
      if(self.checkModified() == True):
        base = filename                                     # default base filename
        if(self.confirmSavePdefFile(title="Save Policy before building?", name=filename) == True):
          # True returned if PDEF was modified and so was saved
          # False returned if not modified so no save needed
          #
          # Note: saving the .pdef and .pdef.txt files here ensures that
          # their LastBuild[Time,Date]Stamp's are updated for this build

          # reuse the base name [with .pdef.txt extention] provided above
          # and don't prompt for a file name again
          #filename = utilities.formFileName(filename, "txt")
          self.printPdefTextFile()

          # originally, filename had no extention so strip it off keeping the user supplied base name
          #filename, ext, ext1 = filename.rsplit('.', 1)

        else:
          # If PDEF not saved, then get the base name for the LCP_POLICY & LCP_POLICY_DATA files to build
          wildcard = "LCP_POLICY (*.pol)|*.pol|" \
                       "All Files (*.*)|*.*"
          title = "Please specify a name for the the LCP_POLICY and LCP_POLICY_DATA files to build."
          dlg = wx.FileDialog(self, title, dirname, filename, wildcard, wx.SAVE|wx.OVERWRITE_PROMPT)

          if dlg.ShowModal() == wx.ID_OK:
            filename = dlg.GetFilename()
            dirname  = dlg.GetDirectory()
            dlg.Destroy()
          else:                                   # user didn't click OK
            dlg.Destroy()
            self.StatusBar.SetStatusText( "No file specified, aborting build" )
            return False

        # originally, filename had no extension so strip it off keeping the user supplied base name
        #filename, ext = filename.rsplit('.', 1)

    elif(buildMode == BUILD_BATCH):
      # originally, filename had no extention so strip it off keeping the user supplied base name
      #filename, ext = filename.rsplit('.', 1)
      pass

    else:   # should never get here
      print("build - unknown buildMode=%d!!!!!!!**********" % (buildMode))

    build.filename = filename
    build.dirname = dirname

    # If PolicyType==LIST, build the LCP_POLICY_DATA struct,
    # which includes creating the LIST_MEASUREMENTS[] used to calculate the pdef.PolicyHash
    #
    text1 = "Building LCP_POLICY files "
    text2 = ".[pol and txt]"
    self.StatusBar.SetStatusText("%s %s %s" % (text1, build.filename, text2))
    #print("build - BuildMode=%d" % (buildMode))   # DBGDBG

    if(build.buildLcpPolicyDataStruct(pdef, self.StatusBar) == False):
      # Abort build if there was a failure, Build can fail reading hash or pcr files
      print("build failed, aborting build")
      return False

    if(buildMode != BUILD_NV_POLICY_ONLY):
      # warn if PolicyType == ANY but BUILD_POLICY_DATA_ONLY was requested
      # since # If PolicyType == ANY, there is no policy data file
      if((buildMode == BUILD_POLICY_DATA_ONLY) and (pdef.PolicyType == DEFINES.ANY)):
        self.StatusBar.SetStatusText("Warning - No Policy Data File (.dat) is built when Policy Type is ANY")

      elif(pdef.PolicyType == DEFINES.LIST):
        # Per TXT SW Dev Guide 3.1.1.1 p50: if PolicyType is ANY, no LCP_POLICY_DATA is expected
        # If PolicyType == ANY, there is no policy data file
        build.buildLcpPolicyDataFile(pdef)

    if(buildMode != BUILD_POLICY_DATA_ONLY):
      # generate the LCP_POLICY files
      if(build.buildRawLcpPolicyFile(pdef, self.StatusBar) == True):    # abort if error
        build.buildTxtLcpPolicyFile(pdef)
        #build.buildXmlLcpPolicyFile(pdef)          # XML output file not requied for LCP2
      else:
        return False
    # Complete build successfully.  Save Pdef file again because pdef.Modified and list.ListModified bits are set False during the build.
    self.writePdefFile()
    return True


  #
  # Do a batch build - defind as:
  #         when tool invoked from cmd line as: txtpolgen2 -open MySystem.pdef -build
  #         validate the specified file ends with .pdef and exists
  #         open it
  #         do a build
  # Assumes file in argv[2] exists and has a .pdef extention
  #
  def batchBuild(self):
    """batchBuild - open and buiild the specified file"""
    #global filename

    # TODO: validate the .pdef, then open it
    #filename = sys.argv[2]
    print("Opening file: %s\%s" % (dirname, filename))
    self.loadAndDisplayPdefFile()

    print("Building")
    self.build(BUILD_BATCH)   # doing a batch build

  #
  # Add List Button clicked
  #
  def onAddListButtonClick(self, event):
    """ onAddListButtonClick - Add List button clicked """

    maxLists = pdef.MaxLists
    listNumber = pdef.NumLists       # current number of lists
    pdef.Modified = True

    if( listNumber+1 == maxLists ):       #  if only space for 1 more list, disable ADD LIST button
      self.addListButton.Enable( False )
    if( listNumber < maxLists ):        # create 1st list panel or update Nth panel
      listNumber += 1
      self.StatusBar.SetStatusText( "Adding List: %i MaxLists=%i" % (listNumber, maxLists))
      self.numOfListsEdit.ChangeValue(str(listNumber))     #  update the number of Lists widget
      pdef.NumLists = listNumber
      pdef.CurrentListView = listNumber

      # NOTE: ChangeValue() does NOT trigger an event [as if the field was edited by the user] as SetValue() does
      self.viewListEdit.ChangeValue( str(listNumber))
      pdef.addPlistDef(listNumber)
      if(listNumber == 1):               # create list panel 1
        # need to enable delete and view list controls
        self.deleteListButton.Enable( True )                 # enable Delete List button
        self.viewListEdit.Enable( True )                  # enable the view list button

        self.viewListLabel.Enable( True )                 # enable the view list label

        list.createListPanel(wx, self.scrollableWindow, listNumber, pdef, self.StatusBar)
      else:                             # update list panel N [< max] to defaults
                                        # PDEF object's LIST section should always contain current values
        list.setListPanelToDefaults(wx, self.scrollableWindow, listNumber, pdef)

    #w, h = self.scrollableWindow.GetMinSize()
    #self.scrollableWindow.SetVirtualSize( (w, h) )
    self.scrollableWindow.Layout()
    #self.Layout()
    #print("AddList: pdef.PolListInfo now = %s" % (pdef.PolListInfo))     # DBGDBG

  #
  # Delete List Button clicked
  #
  def onDeleteListButtonClick(self, event):
    """ onDeleteListButtonClick - Delete List button clicked """

    dlg = wx.MessageDialog(None, "Deleted Lists cannot be recovered. Continue?", 'Confirm List Deletion', wx.YES_NO | wx.ICON_QUESTION)
    response = dlg.ShowModal()
    dlg.Destroy()

    if(response == wx.ID_NO):
      self.StatusBar.SetStatusText( "List Deletion cancelled" )
    else:
      self.StatusBar.SetStatusText( "Deleted List %i, NumLists now %i" % (pdef.CurrentListView, pdef.NumLists-1))

    pdef.Modified = True

    # sanity check: chk that current list indicated by view list is between 1 & PDEF.NumLists
    if((1 <= pdef.CurrentListView) and (pdef.CurrentListView <= pdef.NumLists)):
      currentListObject = pdef.getCurrentListObject()          # delete the current list indicated by view list
      del currentListObject
    else:
      self.StatusBar.SetStatusText( "List Deletion cancelled. CurrentListView=%i, NumLists=%i??" % (pdef.CurrentListView, pdef.NumLists))

    # decrement PDEF.NumLists, if now = 0, ViewList and DeleteList are disabled
    # otherwise, update CurrentListView and display it
    deletedList = pdef.CurrentListView
    pdef.NumLists -= 1
    if(pdef.NumLists == 0):
      pdef.PolListInfo[str(pdef.CurrentListView-1)] = None

      self.viewListLabel.Enable( False )
      self.viewListEdit.Enable( False )
      self.viewListEdit.ChangeValue("")
      self.addListButton.Enable( True )
      self.deleteListButton.Enable( False )
      pdef.CurrentListView = 0
      pdef.NumLists = 0
      self.numOfListsEdit.ChangeValue(str(pdef.NumLists))
      list.hideListPanel()
      self.scrollableWindow.Layout()
      #TODO: WxPython: onDeleteListButtonClick - Layout() didn't resize policyPanel after deleting the last list?  Due to Show/Hide?

      print("DeleteList=0: NumLists=%i CurrentListView=%i" % (pdef.NumLists, pdef.CurrentListView))       # DBGDBG
      print("Delete List: pdef.PolListInfo now = %s" % (pdef.PolListInfo))     # DBGDBG

    else:
      #pdef.PolListInfo[str(pdef.CurrentListView-1)] = None

      pdef.CurrentListView -= 1
      if(pdef.CurrentListView == 0):
        pdef.CurrentListView = 1                    # if list 1 was deleted, and there are >1 lists left, show new list 1
      currentListStr = str(pdef.CurrentListView)
      self.viewListEdit.ChangeValue(currentListStr)
      self.numOfListsEdit.ChangeValue(str(pdef.NumLists))
      list.listLabelNum.ChangeValue(currentListStr)

      print("DeleteList>0: NumLists=%i CurrentListView=%i" % (pdef.NumLists, pdef.CurrentListView))        # DBGDBG
      print("\nDeleted List %i: NumLists=%i\npdef.PolListInfo was %s" % (deletedList, pdef.NumLists, pdef.PolListInfo))     # DBGDBG
      i=deletedList
      end = pdef.NumLists+1
      for i in range(i, end):
        pdef.PolListInfo[str(i-1)] = pdef.PolListInfo[str(i)]
        print("shift %i to %i" % (i, i-1))        # DBGDBG
        i += 1
      pdef.PolListInfo[str(end-1)] = None
      print("delete %i" % (end))        # DBGDBG
      print("pdef.PolListInfo now %s\n" % (pdef.PolListInfo))     # DBGDBG


  def onPolicyVersion(self, event):
    policyversion = event.GetString()
    majorstring, minorstring = policyversion.split('.')
    pdef.PolVersionMajor = int(majorstring)
    pdef.PolVersionMinor = int(minorstring)
    if policyversion == '3.0':
      self.showV31Gui(False)
    else:
      self.showV31Gui(True)

    # go thru each list and change list version number
    listversion = DEFINES.SUPPORTED_LCP_VERSION[policyversion]
    majorstring, minorstring = listversion.split('.')
    for listobj in pdef.PolListInfo.values():
      if listobj != None:
        listobj.ListVersionMajor = int(majorstring)
        listobj.ListVersionMinor = int(minorstring)
    # refresh text in the current list displayed
    if pdef.NumLists != 0:
      list.syncVersion(pdef.Rules)
    pdef.Modified = True

  #
  # MinSinitVersion value changed - update PDEF.SINITMinVersion
  #
  def onMinSinitVersion(self, event):
    """ onMinSinitVersion - MinSinitVersion value was changed"""
    #self.StatusBar.SetStatusText( "You changed MinSinitVersion to %s" % ( event.GetString() ))
    #print("in onMinSinitVersion")   # DBGDBG

    string = event.GetString()
    try:
      value = int(string)
    except:
      self.StatusBar.SetStatusText(  "%s is invalid, Please enter only digits between 0 and 9" % (string))
    else:
      if(int(value) > DEFINES.maxVersion):
        self.StatusBar.SetStatusText( "%i is too large, the max value for MinSinitVersion is %i" % ( int(value), DEFINES.maxVersion ))
      else:
        pdef.SinitMinVersion = int(value)
        pdef.Modified = True
        self.StatusBar.SetStatusText("")   # clear any warnings
    pdef.Modified = True

  #
  # Allow NPW, SINIT cap. in PCR17 or Force Owner Policy 'Policy Control' check box changed
  #
  def setPolicyControl(self, event, bit):
    """ setPolicyControl - the control bits in pdef.PolicyControl.
        This function is call by all CheckBox callback functions for the policy Control Options.
    """
    policyControl = pdef.PolicyControl
    if(event.IsChecked()):
      policyControl |= bit
    else:
      policyControl &= ~bit

    pdef.PolicyControl = policyControl
    pdef.Modified = True
    self.StatusBar.SetStatusText("PDEF.PolicyControl = 0x%x" % (policyControl) )
  
  
  def onNpwPolicyControl(self, event):
    """ onNpwPolicyControl - Allow NPW change"""

    self.setPolicyControl(event, DEFINES.PolicyControlAllowNpwBitMask)


  def onPcr17PolicyControl(self, event):
    """ onPcr17PolicyControl - Allow SINIT Capability in PCR17 change"""

    self.setPolicyControl(event, DEFINES.PolicyControlPcr17BitMask)


  # 'Force Owner Policy' is inverse of 'Force PS PCONFIG',
  #  i.e. they share the same bit in the Control word, and their checkboxes are always opposite values
  #     Enable Force Owner Policy, if PS rules
  #     Enable Force PS PCONFIG,  if PO rules
  #
#  def onForceOwnerPolicyControl(self, event):
#    """ onForceOwnerPolicyControl - Force Owner Policy change"""
#
#    if(event.IsChecked()):
#      self.forceOwnerPolicyValue = True
#    else:
#      self.forceOwnerPolicyValue = False
#    self.setPolicyControl(event, DEFINES.PolicyControlForceOwnerBitMask)


  def onForcePsOrPoPolicyControl(self, event):
    """ onForcePsPconfPolicyControl - Force PS PCONF change"""

    if pdef.Rules == DEFINES.PsRules:
      if(event.IsChecked()):
        self.forceOwnerPolicyValue = True
      else:
        self.forceOwnerPolicyValue = False
    else:
      if(event.IsChecked()):
        self.forcePsPconfValue = True
      else:
        self.forcePsPconfValue = False
    self.setPolicyControl(event, DEFINES.PolicyControlForceOwnerBitMask)


  def onAuxDelete(self, event):
    """ onAuxDelete - AuxDelete Policy change"""

    self.setPolicyControl(event, DEFINES.PolicyControlAUXDeletionControl)


  def onIgnorePsStm(self, event):
    """ onIgnorePsStm - AuxDelete Policy change"""

    self.setPolicyControl(event, DEFINES.PolicyControlIgnorePsStmBitMask)


  def onIignorePsPconf(self, event):
    """ onIignorePsPconf - AuxDelete Policy change"""

    self.setPolicyControl(event, DEFINES.PolicyControlIgnorePsPconfBitMask)


  def onIgnorePsMle(self, event):
    """ onIgnorePsMle - AuxDelete Policy change"""

    self.setPolicyControl(event, DEFINES.PolicyControlIgnorePsMleBitMask)
   
    
  def onBiosRevLimit(self, event):
    """ onBiosRevLimit - BIOS Revocation Limit change"""
    #print("in onBiosRevLimit")   # DBGDBG

    string = event.GetString()
    try:
      value = int(string)
    except:
      self.StatusBar.SetStatusText(  "%s is invalid, Please enter only digits between 0 and 9" % (string))
    else:
      if(int(value) > DEFINES.maxVersion):
        self.StatusBar.SetStatusText( "%i is too large, the max value for BIOS Revocation Limit is %i" % ( int(value),DEFINES. maxVersion ))
      else:
        pdef.MaxBiosMinVersion = int(value)
        pdef.Modified = True
        self.StatusBar.SetStatusText("")   # clear any warnings

  def onSinitRevLimit(self, event):
    """ onSinitRevLimit SINIT Revocation Limit change"""
    #print("in onSinitRevLimit")   # DBGDBG

    string = event.GetString()
    try:
      value = int(string)
    except:
      self.StatusBar.SetStatusText(  "%s is invalid, Please enter only digits between 0 and 9" % (string))
    else:
      if(int(value) > DEFINES.maxVersion):
        self.StatusBar.SetStatusText( "%i is too large, the max value for SINIT Revocation Limit is %i" % ( int(value), DEFINES.maxVersion ))
      else:
        pdef.MaxSinitMinVersion = int(value)
        pdef.Modified = True
        self.StatusBar.SetStatusText("")   # clear any warnings

  def onViewList(self, event):
    """ onViewList - View List value changed"""
    #print("in onViewList")   # DBGDBG
    self.StatusBar.SetStatusText("You changed the View List value to %s" % ( event.GetString() ))

    maxValue = pdef.NumLists
    string = event.GetString()
    try:
      value = int(string)
    except:
      self.StatusBar.SetStatusText(  "%s is invalid, Please enter only digits between 0 and %i" % (string, maxValue))
    else:
      if(value == 0):
        self.StatusBar.SetStatusText( "List number must be > 0" )
        self.viewListEdit.ChangeValue(str(pdef.CurrentListView))        # restore previous value
      elif(value > maxValue):
        self.StatusBar.SetStatusText( "List %i has not been added yet" % ( int(value) ))
        self.viewListEdit.ChangeValue(str(pdef.CurrentListView))        # restore previous value
      else:
        pdef.CurrentListView = int(value)
        pdef.Modified = True
        list.setListPanelToCurrentListView( )   # update the list panel to the specified list
        self.StatusBar.SetStatusText( "Viewing List %d" % ( pdef.CurrentListView ))


  def setAlgMask(self, event, bit, algsAllowed, which):
    """setAlgMask - common code for setting LCP/AutoProtection Algorithms Allowed masks"""

    if(event.IsChecked()):
      newValue = algsAllowed | bit
    else:
      newValue = algsAllowed & ~bit

    if(which == "LCP"):
      pdef.LcpHashAlgMask = newValue
      self.StatusBar.SetStatusText("Algorithm for %s = %d" % (which, pdef.LcpHashAlgMask))
    elif(which == "AP"):
      pdef.AuxHashAlgMask = newValue
      self.StatusBar.SetStatusText("Algorithm for %s = %d" % (which, pdef.AuxHashAlgMask))
    else:
      self.StatusBar.SetStatusText("ERROR: Illegal value = %s passed to setAlgMask(), expected LCP or AP")

    pdef.Modified = True


    print("setAlgMask: LcpHashAlgMask=%x, AuxHashAlgMask=%x" % (pdef.LcpHashAlgMask, pdef.AuxHashAlgMask)) # DBGDBG

  #
  # Utility Functions
  #
  def enableDisableListWidgets( self, value ) :
    """ enableDisableListWidgets """
    self.addListButton.Enable( value )
    self.hashAlgEdit.Enable( value )
    self.numOfListsLabel.Enable( value )

    # if value = True, set NumberOfLists to 0
    if( value == True ):
      self.numOfListsEdit.ChangeValue("0")

  #
  # reset policy panel (& PDEF object) to default vaules
  #
  def setDefaultPdef(self):
    """ setDefaultPdef - set the PDEF to default values"""
    pdef.Modified = False

    self.poRadioButton.SetValue( True )
    pdef.Rules = 1

    pdef.MaxBiosMinVersion = 255
    self.biosEdit.ChangeValue(str(pdef.MaxBiosMinVersion))
    pdef.MaxSinitMinVersion = 255
    self.sinitEdit.ChangeValue(str(pdef.MaxSinitMinVersion))

    pdef.SinitMinVersion = 0
    self.minSinitVersionEdit.ChangeValue(str(pdef.SinitMinVersion))

    pdef.PolicyControl = 0
    self.allowNPW.SetValue(False)
    self.sinitCapabilites.SetValue(False)
    self.auxDelete.SetValue(False)
    self.forceOwnerPolicyValue = False
    self.forcePsPconfValue = True
    self.forcePsOrPo.label = "Force PS PCONF"
    self.forcePsOrPo.SetValue(self.forcePsPconfValue)
    self.setPoRulesMode()
    
    self.anyRadioButton.SetValue( True )
    pdef.PolicyType = 1

    self.hashAlgEdit.Enable( False )
    pdef.HashAlg = DEFINES.TPM_ALG_HASH['SHA256']

    self.numOfListsLabel.Enable( False )
    self.numOfListsEdit.Enable( False )
    self.numOfListsEdit.ChangeValue("")
    self.viewListLabel.Enable( False )
    self.viewListEdit.Enable( False )
    self.addListButton.Enable( False )
    self.deleteListButton.Enable( False )

    self.biosEdit.ChangeValue("255")
    self.sinitEdit.ChangeValue("255")
    self.acmRevLabel.Enable( True )
    self.biosEdit.Enable( True )
    self.sinitEdit.Enable( True )
    self.biosLabel.Enable( True )
    self.sinitLabel.Enable( True )

    pdef.LcpHashAlgMask = DEFINES.TPM_ALG_HASH_MASK['SHA256']
    pdef.AuxHashAlgMask = DEFINES.TPM_ALG_HASH_MASK['SHA256']

    checkedSign = []
    for item in DEFINES.TPM_ALG_SIGN_MASK.keys():
      if(pdef.LcpSignAlgMask & DEFINES.TPM_ALG_SIGN_MASK[item]):
        checkedSign.append(item)
    self.allowedSigSchemesEdit.SetCheckedStrings(checkedSign)

    checkedLCP = []
    for item in DEFINES.TPM_ALG_HASH_MASK.keys():
      if(pdef.LcpHashAlgMask & DEFINES.TPM_ALG_HASH_MASK[item]):
        checkedLCP.append(item)
    self.algAllowedForLcpEdit.SetCheckedStrings(checkedLCP)

    #self.algAllowedForLcpEdit.SetCheckedStrings("")
    #self.allowedSigSchemesEdit.SetCheckedStrings("")
    pdef.PolicyHash = 0
    pdef.LastBuildDateStampYear = 2000
    pdef.LastBuildDateStampMonth = 01
    pdef.LastBuildDateStampDay = 01
    pdef.LastBuildTimeStampHour = 00
    pdef.LastBuildTimeStampMinute = 00
    pdef.LastBuildTimeStampSecond = 00
    pdef.LastBuildTimeStampLowByte = 00
    pdef.CurrentListView = 0
    pdef.NumLists = 0

    # refresh GUI


  def loadAndDisplayPdefFile(self):
    """ loadAndDisplayPdefFile - get a saved pdef object from a PDEF file and update the policy panel"""

    global pdef
    file = None
    try:
      fullFileName = os.path.join(dirname, filename)
      file = open(fullFileName, 'r')
      self.StatusBar.SetStatusText("Opened file: %s" % (filename))
      #TODO: WxPython: loadAndDisplayPdefFile - append current filename to the frame title instead showing in the StatusBar or add a widget?
      pdef = PDEF()
      pdef = pickle.load(file)                 # load pdef from file
      list.hideListPanel()
      print("loadDisplayPdefFile load PDEF")  # DBGDBG
    except IOError:
      self.openError(filename, "IOError")
    #except PickleError:        # not defined in this Python ...
    #  self.openError(filename, "PickleError")
    except AttributeError:
      self.openError(filename, "AttributeError")
    except EOFError:
      self.openError(filename, "EOFError")
    except ImportError:
      self.openError(filename, "ImportError")
    except IndexError:
      self.openError(filename, "IndexError")
    except:
      self.openError(filename, "")

    # Note: list numbering is 1 based.  If pdef.NumLists is less than 1, it must be policy type of Any
    listNum = 1
    if pdef.NumLists >= listNum:
      list.loadAndDisplayPlistDefFile(file, wx, pdef, self.StatusBar, self.scrollableWindow)
    file.close()
    self.restorePanel()

  def openError(self, file, exception):
    """openError - tell user that open failed"""
    self.StatusBar.SetStatusText("Open of pdef file: %s failed. Exception: %s" % (file, exception))
    print("Open of pdef file: %s failed. Exception: %s" % (file, exception)) # DBGDBG

  #
  # write the current PDEF object to a file
  # the policy panel should always display the PDEF object's state
  #
  # file format:
  #     Header
  #     memberName  '=' 'value
  #     ...
  #
  def writePdefFile(self) :
    """ writePdefFile - write the current PDEF object to a file"""
    global dirname, filename

    try:
      f = open(os.path.join(dirname, filename), 'w')
    except IOError:
      self.openError(filename, "IOError")
    #except PickleError:        # not defined in this Python ...
    #  self.openError(filename, "PickleError")
    except AttributeError:
      self.openError(filename, "AttributeError")
    except EOFError:
      self.openError(filename, "EOFError")
    except ImportError:
      self.openError(filename, "ImportError")
    except IndexError:
      self.openError(filename, "IndexError")
    except:
      self.openError(filename, "")

    pickle.dump(pdef, f)       # write out the pdef object

    print("writePdefFile: file: %s" % (filename)) # DBGDBG
    #print("writePdefFile: Rules=%x, PolicyType=%x PolicyControl=%x, NumLists=%x, CurrentListView=%x, MaxBiosMinVersion=%x, MaxSinitMinVersion=%x" %
    #   (pdef.Rules, pdef.PolicyType, pdef.PolicyControl, pdef.NumLists, pdef.CurrentListView,
    #    pdef.MaxBiosMinVersion, pdef.MaxSinitMinVersion))  # DBGDBG

    # Write the PLIST_DEF's
    # pickle.dump of pdef should be sufficient to dump the entire structure.
    f.close()


  def checkModified(self):
    """checkModified - return True if the Policy, List or Element panels were modified, else False"""

    if(pdef.Modified == True):
      #print("checkModified - return PDEF was Modified" )  # DBGDBG
      return True
    elif(list.checkListModified(pdef) == True):
      #print("checkModified - return list was Modified" )  # DBGDBG
      return True
    else:
      #print("checkModified - return nothing Modified" )  # DBGDBG
      return False


  def showV31Gui(self, enable):
    if enable:
      self.ignorePsMle.Show()
      self.ignorePsPconf.Show()
      self.ignorePsStm.Show()
    else:
      self.ignorePsMle.Hide()
      self.ignorePsPconf.Hide()
      self.ignorePsStm.Hide()


  def restorePanel(self):
    """restorePanel - restore the policy panel"""

    print("restorePolicyPanel: Rules=%x, PolicyType=%x PolicyControl=%x, NumLists=%x, CurrentListView=%x, MaxBiosMinVersion=%x, MaxSinitMinVersion=%x" %
          (pdef.Rules, pdef.PolicyType, pdef.PolicyControl, pdef.NumLists, pdef.CurrentListView,
           pdef.MaxBiosMinVersion, pdef.MaxSinitMinVersion))  # DBGDBG

    if(pdef.Rules == DEFINES.PoRules):            # 0=PS, 1=PO
      self.poRadioButton.SetValue(True)
      self.psRadioButton.SetValue(False)
      self.setPoRulesMode()
    else:
      self.psRadioButton.SetValue(True)
      self.poRadioButton.SetValue(False)
      self.setPsRulesMode()

    policyversion = str(pdef.PolVersionMajor)+'.'+str(pdef.PolVersionMinor)
    if policyversion in DEFINES.SUPPORTED_LCP_VERSION:
      self.versionEdit.SetStringSelection(policyversion)
    else:
      print("Invalid Policy version number %s" %(policyversion))

    self.biosEdit.ChangeValue(str(pdef.MaxBiosMinVersion))
    self.sinitEdit.ChangeValue(str(pdef.MaxSinitMinVersion))

    self.minSinitVersionEdit.ChangeValue(str(pdef.SinitMinVersion))

    if(pdef.PolicyControl & DEFINES.PolicyControlAllowNpwBitMask):
      self.allowNPW.SetValue(True)
    if(pdef.PolicyControl & DEFINES.PolicyControlPcr17BitMask):
      self.sinitCapabilites.SetValue(True)
    if(pdef.PolicyControl & DEFINES.PolicyControlForceOwnerBitMask):
      if(pdef.Rules == 0): # ps rule
        self.setPsRulesMode()
      else:
        self.setPoRulesMode()

    if(pdef.PolicyControl & DEFINES.PolicyControlAUXDeletionControl):
       self.auxDelete.SetValue(True)

    policyversion = str(pdef.PolVersionMajor)+'.'+str(pdef.PolVersionMinor)
    if policyversion == '3.0':
      self.showV31Gui(False)
    else:
      self.showV31Gui(True)

    if(pdef.PolicyType == DEFINES.ANY):
      self.anyRadioButton.SetValue(  True  )
      self.listRadioButton.SetValue( False )
      self.enableDisableListWidgets( False )
    else:
      self.anyRadioButton.SetValue(  False )
      self.listRadioButton.SetValue( True  )
      self.enableDisableListWidgets( True  )


    try:
      # Set GUI for Hash Algorithm ComboBox
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == pdef.HashAlg)).next()
      self.hashAlgEdit.SetStringSelection(hashAlgName)
    except StopIteration:
      self.StatusBar.SetStatusText("HashAlg=%d for Hash Algorithm is not supported" % (pdef.HashAlg))

    try:
      # Set GUI Algorithm for Auto-Promotion ComboBox
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH_MASK.items() if (val == pdef.AuxHashAlgMask)).next()
      self.algForApEdit.SetStringSelection(hashAlgName)
    except StopIteration:
      self.StatusBar.SetStatusText("HashAlg=%d for Auto-Promotion is not supported" % (pdef.AuxHashAlgMask))

    checkedLCP = []
    for item in DEFINES.TPM_ALG_HASH_MASK.keys():
      if(pdef.LcpHashAlgMask & DEFINES.TPM_ALG_HASH_MASK[item]):
        checkedLCP.append(item)
    self.algAllowedForLcpEdit.SetCheckedStrings(checkedLCP)

    checkedSign = []
    for item in DEFINES.TPM_ALG_SIGN_MASK.keys():
      if(pdef.LcpSignAlgMask & DEFINES.TPM_ALG_SIGN_MASK[item]):
        checkedSign.append(item)
    self.allowedSigSchemesEdit.SetCheckedStrings(checkedSign)

    self.numOfListsEdit.ChangeValue(str(pdef.NumLists))
    self.viewListEdit.ChangeValue(str(pdef.CurrentListView))
    if(pdef.NumLists > 0):
      self.deleteListButton.Enable()
      self.viewListEdit.Enable()
    else:
      self.deleteListButton.Disable()
      self.viewListEdit.Disable()

    self.biosEdit.ChangeValue(str(pdef.MaxBiosMinVersion))
    self.sinitEdit.ChangeValue(str(pdef.MaxSinitMinVersion))
    pdef.Modified = False;

  #
  # save the current PDEF object to human readable textfile for printing
  # the policy panel should always display the PDEF object's state
  #
  # file format:
  #     Header
  #     memberName  '=' 'value
  #     ...
  #
  def printPdefFile(self):
    """ printPdefFile - save the current PDEF object to human readable textfile for printing"""
    global filename, dirname

    if(self.checkModified() == False):
      self.StatusBar.SetStatusText( "Current file not modified" )
      return
    else:
      #wildcard = "PDEF text file (*.pdef.txt) | *.pdef.txt|" \
      #           "All Files (*.*)    | *.*"
      #title = "Please specify a text file (.txt) to save the PDEF to. This file can be printed from your OS."

      #base = self.getBasePdefFile()
      #dlg = wx.FileDialog(self, title, dirname, base, wildcard, wx.SAVE|wx.OVERWRITE_PROMPT)

      #if dlg.ShowModal() == wx.ID_OK:
      #  filename = dlg.GetFilename()
      #  dirname  = dlg.GetDirectory()
      self.printPdefTextFile()
      #  # originally, filename had no extention so strip it off keeping the user supplied base name
      #  filename, ext, ext1 = filename.rsplit('.', 1)

      #print("printPdefFile - done. filename=%s" % (filename))  # DBGDBG
      #dlg.Destroy()

  def printPdefTextFile(self):
    basefilename, ext = filename.rsplit('.', 1)
    textfile = utilities.formFileName(basefilename, "pdef.txt")
    self.StatusBar.SetStatusText( "Policy saved as text file: %s, which can be printed from your OS" % (textfile ))
    #print("printPdefTextFile: file: %s, PDEF object: %s" % (textfile, pdef)) # DBGDBG
    print("printPdefTextFile: file: %s" % (textfile)) # DBGDBG

    try:
      f = open(os.path.join(dirname, textfile), 'w')
      print("PDEF file: ", textfile, " written on: ", wx.Now(), file=f )
      print("\n", file=f)         # for readability

      print("FileTypeSignature",      " = ", pdef.FileTypeSignature,      file=f)
      print("DefCompany",             " = ", pdef.DefCompany,             file=f)
      print("StructVersion",          " = ", pdef.StructVersion,          file=f)
      print("MaxLists",               " = ", pdef.MaxLists,               file=f)
      print("MaxElements",            " = ", pdef.MaxElements,            file=f)
      print("MaxHashSize",            " = ", pdef.MaxHashSize,            file=f)
      print("MaxHashes",              " = ", pdef.MaxHashes,              file=f)
      print("MaxFileNameSize",        " = ", pdef.MaxFileNameSize,        file=f)
      print("ToolDate",               " = ", pdef.ToolDate,               file=f)
      print("ToolVersion",            " = ", pdef.ToolVersionMajor, ".", pdef.ToolVersionMinor, sep='', file=f)    # suppress separator so 2.2
      print("Rules",                  " = ", pdef.Rules,                  file=f)
      print("Modified",               " = ", pdef.Modified,               file=f)
      print("PolVersion",             " = ", pdef.PolVersionMajor, ".", pdef.PolVersionMinor,  sep='', file=f)    # suppress separator so 1.0
      print("HashAlg",                " = ", pdef.HashAlg,                file=f)
      print("PolicyType",             " = ", pdef.PolicyType,             file=f)
      print("SinitMinVersion",        " = ", pdef.SinitMinVersion,        file=f)
      print("DataRevocationCounters", " = ", pdef.DataRevocationCounters, file=f)    # this is a list!
      print("PolicyControl",          " = ", pdef.PolicyControl,          file=f)
      print("MaxSinitMinVersion",     " = ", pdef.MaxSinitMinVersion,     file=f)
      print("MaxBiosMinVersion",      " = ", pdef.MaxBiosMinVersion,      file=f)
      print("LcpHashAlgMask",         " = ", pdef.LcpHashAlgMask,         file=f)
      print("LcpSignAlgMask",         " = ", pdef.LcpSignAlgMask,         file=f)
      print("AuxHashAlgMask",         " = ", pdef.AuxHashAlgMask,         file=f)
      if(pdef.HashAlg == DEFINES.TPM_ALG_HASH_MASK['SHA256']):
        print("PolicyHash",             " = ", pdef.PolicyHashSha256Hex,  file=f)   # need to print the hex hash
      elif(pdef.HashAlg == DEFINES.TPM_ALG_HASH_MASK['SHA1']):
        print("PolicyHash",             " = ", pdef.PolicyHashSha1Hex,    file=f)   # need to print the hex hash

      # make sure MM, DD, HH, MM and SS fields print as 2 digits with leading 0 ie YYMMDD and HHMMSS
      month = '%02d' % (pdef.LastBuildDateStampMonth)
      day   = '%02d' % (pdef.LastBuildDateStampDay)
      print("LastBuildDateStamp (YYYYMMDD)", " = ", pdef.LastBuildDateStampYear, month, day,  sep='', file=f)
      hour   = '%02d' % (pdef.LastBuildTimeStampHour)
      minute = '%02d' % (pdef.LastBuildTimeStampMinute)
      second = '%02d' % (pdef.LastBuildTimeStampSecond)
      print("LastBuildTimeStamp (HHMMSS)",   " = ", hour, minute, second, sep='', file=f)
      print("CurrentListView",        " = ", pdef.CurrentListView,        file=f)
      print("NumLists",               " = ", pdef.NumLists,               file=f)

      # Show summary: which lists have been added
      print("PolListInfo[0]",         " = ", pdef.PolListInfo['0'],       file=f)
      print("PolListInfo[1]",         " = ", pdef.PolListInfo['1'],       file=f)
      print("PolListInfo[2]",         " = ", pdef.PolListInfo['2'],       file=f)
      print("PolListInfo[3]",         " = ", pdef.PolListInfo['3'],       file=f)
      print("PolListInfo[4]",         " = ", pdef.PolListInfo['4'],       file=f)
      print("PolListInfo[5]",         " = ", pdef.PolListInfo['5'],       file=f)
      print("PolListInfo[6]",         " = ", pdef.PolListInfo['6'],       file=f)
      print("PolListInfo[7]",         " = ", pdef.PolListInfo['7'],       file=f)

      print("\n", file=f)         # for readability

      # print each PLIST_DEF that has been added
      list.printPlistDefs(pdef, f)

    except IOError:
      self.StatusBar.SetStatusText("IOError")
    finally:
      f.close()

  def updateLastBuildDateAndTimeStamps(self):
    """updateLastBuildDateAndTimeStamps - update the LastBuildDateStamp and LastBuildTimeStamp pdef fields"""

    # update the LastBuild[Time,Date]Stamp's
    # Get a datetime object and convert each value to its decimal equivalent
    now = datetime.datetime.now()
    pdef.LastBuildDateStampYear   = int('%04d' % (now.year))     # YYYY as decimal
    pdef.LastBuildDateStampMonth  = int('%02d' % (now.month))    # MM as decimal
    pdef.LastBuildDateStampDay    = int('%02d' % (now.day))      # DD as decimal
    pdef.LastBuildTimeStampHour   = int('%02d' % (now.hour))     # HH as decimal
    pdef.LastBuildTimeStampMinute = int('%02d' % (now.minute))   # MM as decimal
    pdef.LastBuildTimeStampSecond = int('%02d' % (now.second))   # SS as decimal

    #print("updateLastBuildDateAndTimeStamps - YYYY=%04d, MM=%02d, DD=%02d, HH=%02d, MM=%02d, SS=%02d 00=%02d" %
    #     (pdef.LastBuildDateStampYear, pdef.LastBuildDateStampMonth, pdef.LastBuildDateStampDay,
    #       pdef.LastBuildTimeStampHour, pdef.LastBuildTimeStampMinute,
    #       pdef.LastBuildTimeStampSecond, pdef.LastBuildTimeStampLowByte))    # DBGDBG

  def getBasePdefFile(self):
    """getBasePdefFile - get the current pdef file base or use default"""

    # use the current pdef file, if one has been specified
    file = self.pdefFileName.GetValue()
    if(file == 'None'):
      base = "NewPlatform"
    else:
      base, ext = file.rsplit('.', 1)

    return(base)

#################
## MyApp class ##
#################
class MyApp(wx.App):

  def OnInit(self):
    """ onInit - wxWindows calls this method to initialize the application"""

    # Create an instance of our customized Frame class
    frame = MyFrame(None, -1, "TXT Policy Generator")
    frame.Show(True)

    # Tell wxWindows that this is our main window
    self.SetTopWindow(frame)

    # Return a success flag
    return True

app = MyApp(0)     # Create an instance of the application class
#import wx.lib.inspection
#wx.lib.inspection.InspectionTool().Show()
app.MainLoop()     # Tell it to start processing events

#TODO: Med: Open tool by double clicking a .pdef file or dropping one on the tool - WxPython book p530

