#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# using print() built infunction, disable print statement
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
  import shutil
except ImportError:
  raise ImportError, "import OS failed"

from defines import DEFINES
from pdef import PCONF_DEF
from pdef import PCONF_INFO
from ElementGui import *

from util import UTILS
utilities = UTILS()

try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version

#
# TXT Policy Generator Tool
# PCONF Class - Policy Definition File Lists
#
class PCONF( ElementGui ):

  CONST_TITLE = "Choose PCR File"
  CONST_WILDCARD = "Pcr file (*.pcr)|*.pcr|" \
                   "All Files (*.*)|*.*"

  """__init__() - PCONF class constructor"""
  def __init__( self, hashAlg ):
    self.pconfPanelWidgets = []
    self.panelCreated = False

    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
    except StopIteration:
      print("PCONF::__init__ - invalid hashAlg=%d" % (hashAlg))
      return

    self.myIndex = -1   # myIndex is set in createOrShowPanel()
    #if( hashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
    #  self.myIndex = DEFINES.DEFDATA_INDEX_SHA256
    #elif( hashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
    #  self.myIndex = DEFINES.DEFDATA_INDEX_SHA1
    #else:
    #  print("PCONF::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.myHashAlg = hashAlg

  #
  # create the PCONF Panel
  #
  def createOrShowPanel(self, wx, listPanel, parent, pdef, statusBar):
    """createOrShowPanel - create the List Panel"""

    #print("createOrShowPconfPanel hashAlg=%d, panelCreated == %s" % (self.myHashAlg, self.panelCreated))    # DBGDBG
    # 1st time, create the panel
    # nth time, show the panel
    if(self.panelCreated == True):
      self.pcrFileCombo.Clear()
      self.showPanel()
      return

    self.pdef = pdef
    self.parent = parent
    self.listPanel = listPanel
    self.StatusBar = statusBar
    parentSizer = parent.GetSizer()

    currentList = self.pdef.getCurrentListObject()
    self.myIndex = len(currentList.ElementDefData)-1    # Just added the element, the last one should be the one.

    # create the PCONF Panel sizers
    #self.pconfPanelSizer = wx.BoxSizer(wx.VERTICAL)
    pconfGridSizer= wx.GridBagSizer(hgap=5, vgap=5)
    #pconfHorizSizer = wx.BoxSizer(wx.HORIZONTAL)

    self.pconfPanel = wx.Panel(parent, -1)
    self.pconfPanel.SetSizer(pconfGridSizer)

    pconfLabelText1 = "PCONF"
    pconfLabelText2 = "Element"
    pconfLabel1 = wx.StaticText(self.pconfPanel, -1, pconfLabelText1)
    pconfLabel2 = wx.StaticText(self.pconfPanel, -1, pconfLabelText2)
    font = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    pconfLabel1.SetFont( font )
    pconfGridSizer.Add( pconfLabel1, pos=(0, 3))
    self.pconfPanelWidgets.append(pconfLabel1)
    pconfLabel2.SetFont( font )
    pconfGridSizer.Add( pconfLabel2, pos=(0, 4))
    self.pconfPanelWidgets.append(pconfLabel2)

    self.typeLabel = wx.StaticText(self.pconfPanel, label="Type")
    pconfGridSizer.Add( self.typeLabel, pos=(1,3))
    self.pconfPanelWidgets.append(self.typeLabel)
    self.typeEdit  = wx.TextCtrl( self.pconfPanel, value="PCONF", size=(40, -1))
    self.typeEdit.Enable( False )
    pconfGridSizer.Add( self.typeEdit,  pos=(1,4))
    self.pconfPanelWidgets.append(self.typeEdit)

    self.contolOptionsLabel = wx.StaticText(self.pconfPanel, -1, "Control")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.contolOptionsLabel.SetFont( font )

    # override PS policy bit is applicable only if PO policy rules
    self.overridePsPolicy = wx.CheckBox(self.pconfPanel, label="Override PS Policy")

    if(self.pdef.Rules == DEFINES.PoRules):
      self.overridePsPolicy.Enable( True )
    else:
      self.overridePsPolicy.Enable( False )

    pconfGridSizer.Add(self.contolOptionsLabel, pos=(0,8), span=(1,2), flag=wx.BOTTOM, border=5)
    self.overridePsPolicy.Bind(wx.EVT_CHECKBOX, self.onOverridePsPolicy, self.overridePsPolicy)
    pconfGridSizer.Add(self.overridePsPolicy,   pos=(1,8), span=(1,2), flag=wx.BOTTOM, border=5)
    self.pconfPanelWidgets.append(self.contolOptionsLabel)
    self.pconfPanelWidgets.append(self.overridePsPolicy)

    hashAlgStr = self.getHashAlgName()
    if hashAlgStr == None:
      print("createOrShowPconfPanel - invalid myHashAlg=%d" % (self.myHashAlg))

    self.hashAlgLabel = wx.StaticText(self.pconfPanel, label="Hash Algorithm")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.hashAlgLabel.SetFont( font )
    pconfGridSizer.Add(self.hashAlgLabel, pos=(0,20))
    self.pconfPanelWidgets.append(self.hashAlgLabel)

    self.hashAlgEdit = wx.TextCtrl( self.pconfPanel, size=(75, -1), value=hashAlgStr )
    self.hashAlgEdit.Enable(False)
    pconfGridSizer.Add(self.hashAlgEdit, pos=(1,20))
    self.pconfPanelWidgets.append(self.hashAlgEdit)

    pcrFile = ""
    self.pcrFileFileLabel = wx.StaticText(self.pconfPanel, label="PCR File")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    self.pcrFileFileLabel.SetFont( font )
    pconfGridSizer.Add( self.pcrFileFileLabel, pos=(2,3))
    self.pconfPanelWidgets.append(self.pcrFileFileLabel)

    self.pcrFileCombo  = wx.ComboBox( self.pconfPanel, value=pcrFile, size=(200, -1), choices=pcrFile, style=wx.CB_DROPDOWN)
    self.pcrFileCombo.Enable( False )  # prevent selection since pulldown is empty
    self.pcrFileCombo.Bind(wx.EVT_TEXT, self.onPcrFileCombo, self.pcrFileCombo)
    pconfGridSizer.Add( self.pcrFileCombo,  pos=(2,4))
    self.pconfPanelWidgets.append(self.pcrFileCombo)

    self.fileSelectionLabel = wx.StaticText(self.pconfPanel, label="Selected File")
    pconfGridSizer.Add( self.fileSelectionLabel, pos=(7,3))
    self.pconfPanelWidgets.append(self.fileSelectionLabel)
    self.fileSelectionEdit  = wx.TextCtrl( self.pconfPanel, value=" ", size=(40, -1))
    self.fileSelectionEdit.Enable( False )
    pconfGridSizer.Add( self.fileSelectionEdit,  pos=(7,4))
    self.pconfPanelWidgets.append(self.fileSelectionEdit)

    self.fileCntLabel = wx.StaticText(self.pconfPanel, label="Number of Files")
    pconfGridSizer.Add( self.fileCntLabel, pos=(8,3))
    self.pconfPanelWidgets.append(self.fileCntLabel)
    self.fileCntEdit  = wx.TextCtrl( self.pconfPanel, value="0", size=(40, -1))
    self.fileCntEdit.Enable( False )
    pconfGridSizer.Add( self.fileCntEdit,  pos=(8,4))
    self.pconfPanelWidgets.append(self.fileCntEdit)

    self.updateButton = wx.Button( self.pconfPanel, -1,      label="Apply PCR Selection")
    self.updateButton.Enable( False )
    pconfGridSizer.Add( self.updateButton, pos=(7,8))
    self.pconfPanelWidgets.append(self.updateButton)
    self.updateButton.Bind(wx.EVT_BUTTON, self.onUpdateButtonClick, self.updateButton)

    self.addButton = wx.Button( self.pconfPanel, -1,      label="    Add   ")
    pconfGridSizer.Add( self.addButton, pos=(3,4))
    self.pconfPanelWidgets.append(self.addButton)
    self.addButton.Bind(wx.EVT_BUTTON, self.onAddButtonClick, self.addButton)

    self.removeButton = wx.Button( self.pconfPanel, -1,      label="  Remove  ")
    self.removeButton.Enable( False )
    pconfGridSizer.Add( self.removeButton, pos=(4,4))
    self.pconfPanelWidgets.append(self.removeButton)
    self.removeButton.Bind(wx.EVT_BUTTON, self.onRemoveButtonClick, self.removeButton)

    #self.pcrSelectionLabel = wx.StaticText(self.pconfPanel, -1, "PCR Selection")
    #font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    #self.pcrSelectionLabel.SetFont( font )
    self.pcrSelectionLabel1 = wx.StaticText(self.pconfPanel, -1, "PCR ")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.pcrSelectionLabel1.SetFont( font )
    self.pcrSelectionLabel2 = wx.StaticText(self.pconfPanel, -1, "Selection")
    self.pcrSelectionLabel2.SetFont( font )

    self.pcr0 = wx.CheckBox(self.pconfPanel, label="0")
    self.pcr1 = wx.CheckBox(self.pconfPanel, label="1")
    self.pcr2 = wx.CheckBox(self.pconfPanel, label="2")
    self.pcr3 = wx.CheckBox(self.pconfPanel, label="3")
    self.pcr4 = wx.CheckBox(self.pconfPanel, label="4")
    self.pcr5 = wx.CheckBox(self.pconfPanel, label="5")
    self.pcr6 = wx.CheckBox(self.pconfPanel, label="6")
    self.pcr7 = wx.CheckBox(self.pconfPanel, label="7")

    self.pcrSelectionCheckboxes =[self.pcr7, self.pcr6, self.pcr5, self.pcr4,
                             self.pcr3, self.pcr2, self.pcr1, self.pcr0]

    self.enableDisablePcrSelectionCheckBoxes(False)  # disable the check boxes til the 1st file is added


    #pconfGridSizer.Add(self.pcrSelectionLabel, pos=(2,8), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcrSelectionLabel1, pos=(2,6), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcrSelectionLabel2, pos=(2,8), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr7,   pos=(3,6), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr6,   pos=(4,6), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr5,   pos=(5,6), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr4,   pos=(6,6), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr3,   pos=(3,8), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr2,   pos=(4,8), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr1,   pos=(5,8), span=(1,2), flag=wx.BOTTOM, border=5)
    pconfGridSizer.Add(self.pcr0,   pos=(6,8), span=(1,2), flag=wx.BOTTOM, border=5)

    #self.pconfPanelWidgets.append(self.pcrSelectionLabel)
    self.pconfPanelWidgets.append(self.pcrSelectionLabel1)
    self.pconfPanelWidgets.append(self.pcrSelectionLabel2)
    self.pconfPanelWidgets.append(self.pcr0)
    self.pconfPanelWidgets.append(self.pcr1)
    self.pconfPanelWidgets.append(self.pcr2)
    self.pconfPanelWidgets.append(self.pcr3)
    self.pconfPanelWidgets.append(self.pcr4)
    self.pconfPanelWidgets.append(self.pcr5)
    self.pconfPanelWidgets.append(self.pcr6)
    self.pconfPanelWidgets.append(self.pcr7)

    self.pconfPanelWidgets.append(self.pconfPanel)
    #print("PCONF createPanel - hashAlg=%d, len(Widgets)=%d" % (self.myHashAlg, len(self.pconfPanelWidgets)))  #DBGDBG
    #pconfHorizSizer.Add(pconfGridSizer,  0, wx.ALL, 5)
    #self.pconfPanelSizer.Add(pconfHorizSizer, 0, wx.ALL, 5)
    #parent.SetSizerAndFit(self.pconfPanelSizer)
    parentSizer.Add(self.pconfPanel)
    w,h = parentSizer.GetMinSize()
    parent.SetVirtualSize((w,h))
    print("parent sizer type = %s  size = %d, %d" %(type(parentSizer).__name__, w, h))
    parent.Layout()
    # call restorePanel to sync data to GUI
    self.restorePanel(currentList, pdef.MaxHashes)
    self.panelCreated = True

  def hidePanel(self):
      """hidePanel - hide the Pconf panel"""
      #print("PCONF hidePanel - hashAlg=%d, len(Widgets)=%d" % (self.myHashAlg, len(self.pconfPanelWidgets)))  #DBGDBG
      for i in self.pconfPanelWidgets:
          i.Hide()


  def showPanel(self):
    """showPanel - show the Pconf panel"""
    #print("PCONF showPanel - hashAlg=%d, len(Widgets)=%d" % (self.myHashAlg, len(self.pconfPanelWidgets)))  #DBGDBG
    if self.panelCreated:
      for i in self.pconfPanelWidgets:
        i.Show()
      parentSizer = self.parent.GetSizer()
      w,h = parentSizer.GetMinSize()
      self.parent.SetVirtualSize((w,h))


  def setElementToDefaults(self):
    """setElementToDefaults - PCONF"""

    self.pcrFileCombo.SetValue(' ')
    self.clearPcrCheckBoxes()

    currentList = self.pdef.getCurrentListObject()
    currentList.ElementDefData[self.myIndex].IncludeInList = False
    currentList.ElementDefData[self.myIndex].HashAlg      = self.myHashAlg
    currentList.ElementDefData[self.myIndex].Control      = 0
    currentList.ElementDefData[self.myIndex].NumbHashes   = 0
    currentList.ElementDefData[self.myIndex].CurrentView  = 0
    currentList.ElementDefData[self.myIndex].PcrInfoSrc = []

  def onOverridePsPolicy(self, event):
    """onOverridePsPolicy - update the Control field"""

    # set/clear bit 0 per MLE Dev Guide PolEltControl def
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    currentList.ElementDefData[self.myIndex].Control = event.Checked()
    #print("onOverridePsPolicy Control=%d Event=%d" % (currentList.ElementDefData[self.myIndex].Control , event.IsChecked()))

  def onPcrFileCombo(self, event):
    """onPcrFileCombo - update which PCR file is selected"""
    # Get the PcrInfo entry selected by the user and save it in CurrentView
    currentSelection = self.pcrFileCombo.GetSelection()
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    currentList.ElementDefData[self.myIndex].CurrentView = currentSelection
    #print("onPcrFileCombo: currentSelection=%d, NumbHashes=%d" % (currentSelection, currentList.ElementDefData[self.myIndex].NumbHashes)) #DBGDBG

    # set the checkboxes to match the current selection and show which element is selected
    self.showSelection(currentSelection)
    pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[currentSelection]
    pcrSelection = pconf_info.pcrSelect[0]
    self.setPcrSelectionCheckboxes(pcrSelection)

  def onUpdateButtonClick(self, event):
    """onUpdateButtonClick - update the PCR select per the PCR0-7 checkboxes for the current file"""
    self.updatePcrFileCombo()

  def updatePcrFileCombo(self):
    # update the selected PcrInfoSrc[i].pcrSelect[0] with the PCR Selection info set by the user
    # where i = currentList.ElementDefData[self.myIndex].CurrentView = user's current selection
    # this indicates which PCRs in the file are evaluated
    bit = 0
    byte = 0
    for eachCheckbox in self.pcrSelectionCheckboxes:
      if(eachCheckbox.IsChecked() == True):
        x = 1 << (7-bit)
        #print("updatePcrFileCombo - bit %x is checked, x=%x" % (bit, x)) #DBGDBG
      else:
        x = 0

      bit += 1
      byte |= x

    #print("updatePcrFileCombo - byte=%x" % (byte)) #DBGDBG
    newPcrSelection = self.makeListWithEntryForEachBitInByte(byte)

    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    #currentEntrySelected = self.pcrFileCombo.GetSelection()
    currentEntrySelected = currentList.ElementDefData[self.myIndex].CurrentView
    #print("updatePcrFileCombo - currentEntrySelected=%x*****" % (currentEntrySelected)) #DBGDBG
    pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[currentEntrySelected]
    pconf_info.pcrSelect[0] = newPcrSelection
    #print("updatePcrFileCombo -currentEntrySelected=%d=%s newPcrSelection=%s" % (currentEntrySelected, pconf_info, newPcrSelection)) #DBGDBG

    filename = pconf_info.pcrFile
    value = str(newPcrSelection) + " " + filename

    # replace the selection
    # update the choices list

    #TODO: wxPython: updatePcrFileCombo - ComboBox.Replace doesn't work so doing .Clear() .Append's - better way?
    # XXXXXXX   self.pcrFileCombo.Replace( currentEntrySelected, value )    XXXXXXXXXX
    # Since ComboBox.Replace doesn't work,
    # Use .Clear() to clear the choices then iterate thru and reconstruct the choices with .Append(eachChoice)

    self.pcrFileCombo.Clear()
    self.pcrFileCombo.SetValue( value )
    fileCnt = currentList.ElementDefData[self.myIndex].NumbHashes
    i = 0
    #print("updatePcrFileCombo: NumbHashes=%d**StartOfWhile**" % (fileCnt))  #DBGDBG
    while(i < fileCnt):
      pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[i]
      #print("Update: Pconf_info%d=%s NumbHashes=%d, pcrFile=%s pcrSelect[0]=%s  --start of loop--" %
      #    (i, pconf_info, fileCnt, pconf_info.pcrFile, pconf_info.pcrSelect[0]))    # DBGDBG
      bit = 0
      byte = 0
      for eachPcr in pconf_info.pcrSelect[0]:   # pcrSelect[0] ordered 7:0, pcrSelectionCheckboxes ordered 0:7
        if(eachPcr == 1):
          x = 1 << (7-bit)
          #print("updatePcrFileCombo: i=%d: bit %x is set, x=%x byte=%x" % (i, 7-bit, x, byte)) #DBGDBG
        else:
          x = 0

        bit += 1
        byte |= x

      #print("updatePcrFileCombo - byte=%x" % (byte)) #DBGDBG
      newPcrSelection = self.makeListWithEntryForEachBitInByte(byte)
      filename = pconf_info.pcrFile
      value = str(newPcrSelection) + " " + filename
      self.pcrFileCombo.Append(value)
      #print("updatePcrFileCombo: i=%d  value=%s  --end of loop--" % (i, value ))    # DBGDBG
      i += 1


  def onAddButtonClick(self, event):
    """onAddButtonClick - add a PCR file to the list"""
    # Present dialogue for user to select a PCR file
    # Leave PCR Selection checkboxes as is so same setting can be used on next file

    filepath, filename = self.selectFile()

    if (filename == ''):
      # selectFile() operation has been cancelled.
      return

    # validate that the specified PCR file is properly formatted
    currentList = self.pdef.getCurrentListObject()
    result = utilities.verifyPcrFile(os.path.join(filepath, filename), currentList.ElementDefData[self.myIndex].HashAlg)
    # Note: verifyPcrFile() returns [FileValid, FileType], but only FileValid is used here
    if( result[0] == False):
      return

    self.copyFile(filepath, filename)
    self.StatusBar.SetStatusText("Validated file %s." % (filename))

    # incr currentList.ElementDefData[self.myIndex].NumbHashes and update NumberOfFiles widget
    self.setListModified()
    fileCnt = currentList.ElementDefData[self.myIndex].NumbHashes
    fileCnt += 1
    self.fileCntEdit.ChangeValue(str(fileCnt))
    currentList.ElementDefData[self.myIndex].NumbHashes = fileCnt

    # add a PCONF_INFO to PCONF_DEF.PcrInfoSrc[] for this PCR file
    pconf_info = PCONF_INFO()                                           # create a PCONF_INFO
    currentList.ElementDefData[self.myIndex].PcrInfoSrc.append(pconf_info)
    #print("pconf_info: NumbHahses=%x pcrSelect[0]=%x, pcrFile=%s" % (fileCnt, pconf_info.pcrSelect[0], pconf_info.pcrFile))  # DBGDBG

    pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[fileCnt-1]         # add the PCONF_INFO to PCONF_DEF

    # Set currentList.ElementDefData[self.myIndex].PcrInfoSrc[i].pcrSelect[0] = 0
    # Set currentList.ElementDefData[self.myIndex].PcrInfoSrc[i].pcrFile = the selected file
    #   where i = currentList.ElementDefData[self.myIndex].CurrentView = user's current selection
    # Concatenate "PcrInfoSrc[i].pcrSelect" and "PcrInfoSrc[i].pcrFile"  per fig 9
    # display/append that concatenated value to the comboBox.  ex: "00000000 PlatformA_BiosD28.pcr"
    pconf_info.pcrFile = filename
    pcrSelectBits = [0,0,0,0,0,0,0,0]      # list of each bit in pcrSelect[0] = 00000000
    pconf_info.pcrSelect[0] = pcrSelectBits
    currentList.ElementDefData[self.myIndex].CurrentView = fileCnt-1
    print("Add: Pconf_info%d=%s NumbHashes=%d, pcrFile=%s pcrSelect[0]=%s" %
          (fileCnt-1, pconf_info, fileCnt, pconf_info.pcrFile, pconf_info.pcrSelect[0]))    # DBGDBG

    value = str(pcrSelectBits) + " " + filename
    self.pcrFileCombo.SetValue( value )
    self.pcrFileCombo.Append( value )

    # disable ADD button if NumbHashes now > MaxHashes, unless MaxHashes is 0 indicating no limit on the number of files
    if(self.pdef.MaxHashes != 0):
      if(fileCnt > self.pdef.MaxHashes):
          self.addButton.Enable( False )

    # enable REMOVE and UPDATE buttons and PCR File combo box ifNumbHashes > 1
    if(fileCnt > 0):
        self.updateButton.Enable( True )
        self.removeButton.Enable( True )
        self.pcrFileCombo.Enable( True )
        self.enableDisablePcrSelectionCheckBoxes(True)

    self.showSelection(currentList.ElementDefData[self.myIndex].CurrentView)

  def onRemoveButtonClick(self, event):
    """onRemoveButtonClick - Remove the current PCR file from the list"""

    # confirm the remove
    dlg = wx.MessageDialog(None, "Confirm removal of selected PCR file?", 'Confirm Remove', wx.YES_NO | wx.ICON_QUESTION)
    response = dlg.ShowModal()
    dlg.Destroy()

    if(response == wx.ID_NO):
      self.StatusBar.SetStatusText( "Remove cancelled" )
      return

    # remove the selected PCRInfoSrc entry from the comboBox, ie entry: currentList.ElementDefData[self.myIndex].CurrentView
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    currentSelection = currentList.ElementDefData[self.myIndex].CurrentView
    self.pcrFileCombo.Delete(currentSelection)

    # show entry 0
    newView = 0
    self.pcrFileCombo.SetSelection(newView)
    currentList.ElementDefData[self.myIndex].CurrentView = newView

    # also remove the entry from ElementDefData[]
    del currentList.ElementDefData[self.myIndex].PcrInfoSrc[currentSelection]

    # decr currentList.ElementDefData[self.myIndex].NumbHashes and update currentList.ElementDefData[self.myIndex].CurrentView
    # decr currentList.ElementDefData[self.myIndex].NumbHashes and update NumberOfFiles widget
    fileCnt = currentList.ElementDefData[self.myIndex].NumbHashes
    fileCnt -= 1
    self.fileCntEdit.ChangeValue(str(fileCnt))
    currentList.ElementDefData[self.myIndex].NumbHashes = fileCnt

    # DBGDBG
    print("onRemoveButtonClick - removed %d, NumbHashes=%d currentSelection=%d" % (currentSelection, fileCnt, currentSelection)) #DBGDBG
    if(fileCnt > 0):                                              # DBGDBG - verify ElementDefData vs. Add's prints
      i=0                                                         # DBGDBG
      while(i < fileCnt):                                         # DBGDBG
        pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[i]       # DBGDBG
        print("Remove: Pconf_info%d=%s, pcrFile=%s pcrSelect[0]=%s" % (i, pconf_info, pconf_info.pcrFile, pconf_info.pcrSelect[0]))  # DBGDBG
        i += 1                                                    # DBGDBG
    # DBGDBG

    if(response == wx.ID_YES):
      if(fileCnt > 0):
        self.showSelection(newView)
        # update the PCR Selection checkboxes to match the new selection
        pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[newView]
        pcrSelection = pconf_info.pcrSelect[0]
        self.setPcrSelectionCheckboxes(pcrSelection)
      else:
        # no more files, disable Remove & Update
        self.updateButton.Enable( False )
        self.removeButton.Enable( False )
        self.pcrFileCombo.Enable( False )
        self.enableDisablePcrSelectionCheckBoxes(False)
        self.fileSelectionEdit.ChangeValue("")
        self.clearPcrCheckBoxes()
        self.StatusBar.SetStatusText( "PCR file removed" )

    # reenable ADD button if NumbHashes is now < MaxHashes
    if(self.pdef.MaxHashes != 0):
      if(fileCnt < self.pdef.MaxHashes):
          self.addButton.Enable( True )

  def clearPcrCheckBoxes(self):
    """clearPcrCheckBoxes - clear the PCR check boxes"""
    for eachBox in self.pcrSelectionCheckboxes:
      eachBox.SetValue(False)

  #
  # Form an 8 entry list where each member represents the value of each bit in the specified byte
  # ordered from bit 7 to bit 0
  # Example:  if byte = 0x35 Output is [0,0,1,1,0,1,0,1]
  #
  def makeListWithEntryForEachBitInByte(self, byte):
    """makeListWithEntryForEachBitInByte - Form an 8 entry list where each member represents the value of each bit in the specified byte  """

    bit = 0x80
    cnt = 0
    pcrSelectBits = [0, 1, 2, 3, 4, 5, 6, 7]    # initial values will be overwritten
    #print("Bits=%s pcrSelectBits[cnt]=%x cnt=%x bit=%x byte=%x" % (pcrSelectBits, pcrSelectBits[cnt], cnt, bit, byte)) #DBGDBG
    while(bit >= 0x01):     # check each bit from bit 7 thru bit 0
      if(byte & bit != 0):
        pcrSelectBits[cnt] = 1
      else:
        pcrSelectBits[cnt] = 0
      #print("Bits=%s, pcrSelectBits[cnt]=%x, cnt=%x bit=%x byte=%x" % (pcrSelectBits, pcrSelectBits[cnt], cnt, bit, byte)) #DBGDBG
      bit >>= 1
      cnt += 1

    return(pcrSelectBits)


  # show current selection and prompt user to select PCRs and click UPDATE for selected file
  def showSelection(self, currentSelection):
    """showSelection - show user which element is selected"""
    self.StatusBar.SetStatusText("PCR File %d is selected. To change PCR Selections, Set the PCR[0-7] check boxes, and click Apply PCR Selection"
      % (currentSelection+1) )
    self.fileSelectionEdit.ChangeValue(str(currentSelection+1))

  def enableDisablePcrSelectionCheckBoxes(self, value):
    """setPcrSelectionCheckBoxes - enable/disable the PCR Selection check boxes  """
    for eachBox in self.pcrSelectionCheckboxes:
      eachBox.Enable(value)

  def setPcrSelectionCheckboxes(self, pcrSelection):
    """setPcrSelectionCheckboxes - set the PCR selection checkboxes per the pcrSelection list"""
    i=0
    for eachCheckbox in self.pcrSelectionCheckboxes:
      if(pcrSelection[i] == 1):
        eachCheckbox.SetValue(True)
      else:
        eachCheckbox.SetValue(False)

      i += 1


  def writePconfDef(self, pconfDefData, f):
    """writePconfDef - write the PCONF_DEF to the specified file"""

    print("writePconfDef dump pconfDefData, hashAlg=%d"  % (self.myHashAlg))  # DBGDBG
    pickle.dump(pconfDefData, f)       # write out the pconfDefData object

    i = 0
    for eachPconfInfo in pconfDefData.PcrInfoSrc:
      #print("writePconfDef: pconfInfo %x" % (i))         # for readability
      self.writePconfInfo(eachPconfInfo, i, f)
      i += 1

  def writePconfInfo(self, pconfInfo, index, f):
    """writePconfInfo - write the PCONF_INFO to the specified file"""

    print("writePconfInfo dump pconfInfo")  # DBGDBG
    pickle.dump(pconfInfo, f)       # write out the pconfInfo object

  def setPanelToDefaults(self):
    """setPanelToDefaults - restore defaults to pconf panel widgets"""

    self.overridePsPolicy.SetValue(0)
    self.pcrFileCombo.SetValue("")
    self.addButton.Enable(True)
    self.removeButton.Enable(False)
    self.updateButton.Enable(False)
    self.fileCntEdit.ChangeValue("0")
    self.fileSelectionEdit.ChangeValue("")
    self.enableDisablePcrSelectionCheckBoxes(False)
    self.clearPcrCheckBoxes()

  def restorePanel(self, currentList, maxHashes):
    """restorePanel - restore the PCONF element panel from the specified PLIST_DEF"""

    print("restorePanel - Rules=%d, PCONF Control=%d" % (self.pdef.Rules, currentList.ElementDefData[self.myIndex].Control)) # DBGDBG

    # update Override PS Policy checkbox
    self.overridePsPolicy.SetValue(currentList.ElementDefData[self.myIndex].Control)
    if(self.pdef.Rules == DEFINES.PoRules):
      self.overridePsPolicy.Enable( True )
    else:
      self.overridePsPolicy.Enable( False )

    listversion = str(currentList.ListVersionMajor)+'.'+str(currentList.ListVersionMinor)
    if listversion == '2.0':
      self.showV20Gui(True)
    else:
      self.showV20Gui(False)

    # If MaxHashes not 0, Only enable Add if < MaxHashes files
    numbHashes = currentList.ElementDefData[self.myIndex].NumbHashes
    flag = True
    if(maxHashes != 0):
      if(numbHashes >= maxHashes):
        flag = False                              # don't enable add
    self.addButton.Enable(flag)

    # if >0 hashes
    #     enable remove and update
    #     select 1st file and set SelectedFile
    flag = False
    if(numbHashes > 0):
      flag = True
      self.pcrFileCombo.SetSelection(0)
      self.pcrFileCombo.Enable(True)
      self.fileSelectionEdit.ChangeValue("1")

    self.removeButton.Enable(flag)
    self.updateButton.Enable(flag)

    # set Number of Files
    self.fileCntEdit.ChangeValue(str(numbHashes))

    # update PCR Selection checkboxes for selected file
    currentEntrySelected = currentList.ElementDefData[self.myIndex].CurrentView
    print("restorePanel - PCONF currentEntrySelected=%d numbHashes=%d" % (currentEntrySelected, numbHashes)) # DBGDBG
    if(numbHashes > 0):
      self.showSelection(currentEntrySelected)
      pconf_info = currentList.ElementDefData[self.myIndex].PcrInfoSrc[currentEntrySelected]
      pcrSelection = pconf_info.pcrSelect[0]
      self.setPcrSelectionCheckboxes(pcrSelection)
      self.pcrFileCombo.SetSelection(currentEntrySelected)
      self.pcr0.Enable(True)
      self.pcr1.Enable(True)
      self.pcr2.Enable(True)
      self.pcr3.Enable(True)
      self.pcr4.Enable(True)
      self.pcr5.Enable(True)
      self.pcr6.Enable(True)
      self.pcr7.Enable(True)

      # Now form PCR File combo selection and choices list
      # ***Note that this code requires that the PCR Selection checkboxes have
      # been updated all ready********************************************
      self.updatePcrFileCombo()


  #def setListModified(self):
  #  """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""
  #
  #  currentList = self.pdef.getCurrentListObject()
  #
  #  #print("PCONF setListModified - ListModified was %s" % (currentList.ListModified))  # DBGDBG
  #  if(currentList.ListModified == False):
  #    currentList.RevocationCounter += 1
  #    self.listPanel.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
  #    currentList.ListModified = True

  # the last function in the file doesn't show up in the scope list in Understand for some reason!
  def stub(self):
    pass
