#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# using print() built infunction, disable print statement
from __future__ import print_function

import string

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
from pdef import PLIST_DEF, MLE_DEF, PCONF_DEF, SBIOS_DEF
from LcpPolicy import LCP_POLICY2, LCP_SIGNATURE2
from util import UTILS
utilities = UTILS()

from sbios import SBIOS
from mle import MLE
from pconf import PCONF
from stm import STM
from sbiosLegacy import SBIOSLegacy
from pconfLegacy import PCONFLegacy
from mleLegacy import MLELegacy
from pdef import *


try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version


import array
import base64
from struct import *


# TXT Policy Generator Tool
# List Class - Policy Definition File Lists
#
class LIST( object ):
  """__init__() - List class constructor"""
  def __init__( self ):
    """LIST __init__ constructor"""
    self.listPanelWidgets = []
    self.visibleElement = DEFINES.ELEMENT_NAME_NONE
    self.includedElements = []
    #print("in LIST __init__() listPanelWidgets=%s" % (self.listPanelWidgets))   # DBGDBG

  #
  # create the List Panel
  #     LIST X
  #       Version 2.0   Number of 0 Select  NONE      DELETE ELEMENT
  #                     Elements    Element
  #       Revocation 23 [] Signed                     ADD SBIOS
  #       Count            Key File my.key  BROWSE    ADD MLE
  #       Allowed    23    Key Size 2048  RSA PKCS1.5 ADD PCONF
  #      RESET   [] Sync                  Algorithm
  #
  def createListPanel(self, wx, parent, listNumber, pdef, statusBar):
    """createListPanel - create the List Panel"""

    #print("createListPanel - list %i" % (listNumber))
    self.pdef = pdef
    self.StatusBar = statusBar
    self.parent = parent
    parentSizer = parent.GetSizer()

    # create the List Panel sizers
    self.listPanel = wx.Panel(parent, -1)
    self.listPanelSizer = wx.GridBagSizer(hgap=5, vgap=5)
    self.listPanel.SetSizer(self.listPanelSizer)
    #listHorizSizer = wx.BoxSize4r(wx.HORIZONTAL)

    #listLabelText = "LIST " + str(listNumber)
    listLabelText = "LIST"
    self.listLabel = wx.StaticText(self.listPanel, -1, listLabelText)
    font = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.listLabel.SetFont( font )
    self.listPanelSizer.Add( self.listLabel, pos=(0, 0))
    self.listPanelWidgets = [self.listLabel]

    self.listLabelNum = wx.TextCtrl( self.listPanel, value="X", size=(30, -1))
    self.listLabelNum.Enable( False )              # LIST num cannot be modified by user
    self.listLabelNum.SetFont( font )
    #self.listLabelNum.SetBackgroundColour(self.listPanel.GetBackgroundColour())            # no change to color??   Fore or Background N/C
    self.listLabelNum.SetFocus()
    self.listLabelNum.Refresh()   # no help
    self.listLabelNum.ChangeValue(str(listNumber))
    self.listPanelSizer.Add( self.listLabelNum,  pos=(0,1))
    self.listPanelWidgets.append(self.listLabelNum)

    # LIST Version text box - PDEF.PolList[n].ListVersion
    # Change list version number to corresponds to policy version number
    #policyversion = str(pdef.PolVersionMajor) + '.' + str(pdef.PolVersionMinor)
    #listversion = DEFINES.SUPPORTED_LCP_VERSION[policyversion]
    #majorstring, minorstring = listversion.split('.')
    #self.pdef.PolListInfo[str(listNumber-1)].ListVersionMajor = int(majorstring)
    #self.pdef.PolListInfo[str(listNumber-1)].ListVersionMinor = int(minorstring)
    self.versionLabel = wx.StaticText(self.listPanel, label="Version: ", size = (90, -1), style = wx.ALIGN_RIGHT)
    self.listPanelSizer.Add( self.versionLabel, pos=(1,0))
    self.listPanelWidgets.append(self.versionLabel)
    version = str(self.pdef.PolListInfo[str(listNumber-1)].ListVersionMajor)+"."+str(self.pdef.PolListInfo[str(listNumber-1)].ListVersionMinor)
    self.versionEdit  = wx.TextCtrl( self.listPanel, value=version, size=(30, -1))
    self.versionEdit.Enable( False )              # Version cannot be modified
    self.listPanelSizer.Add( self.versionEdit,  pos=(1,1))
    self.listPanelWidgets.append(self.versionEdit)

    # Number Elements text box - number of elements that are marked VALID
    self.numberElementsLabel = wx.StaticText(self.listPanel, label="Number of Elements ")
    self.listPanelSizer.Add( self.numberElementsLabel, pos=(2,2))
    self.listPanelWidgets.append(self.numberElementsLabel)
    self.numberElementsEdit  = wx.TextCtrl( self.listPanel, value="0", size=(30, -1))
    self.numberElementsEdit.Disable()
    self.listPanelSizer.Add( self.numberElementsEdit,  pos=(2,3))
    self.listPanelWidgets.append(self.numberElementsEdit)

    # Select Element Control - PDEF.PolList[n].CurrentElementView
    #     Allows user to select which elements to view
    #     Disabled when NumberOfElements = 0
    #     SBIOS is only valid if PS rules.
    #     MLE and PCONF are valid for both.
    self.selectElementList = [DEFINES.ELEMENT_NAME_NONE]

    self.selectElementLabel = wx.StaticText(self.listPanel, label="\nView Element")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    self.selectElementLabel.SetFont( font )
    self.listPanelSizer.Add(self.selectElementLabel, pos=(3,2))
    self.listPanelWidgets.append(self.selectElementLabel)

    self.selectElementEdit = wx.ComboBox( self.listPanel, size=(100, -1), value=DEFINES.ELEMENT_NAME_NONE, choices=self.selectElementList, style=wx.CB_READONLY )
    self.selectElementEdit.Enable( False )
    self.selectElementEdit.SetSelection(0)
    self.listPanelSizer.Add(self.selectElementEdit, pos=(4,2))
    self.selectElementEdit.Bind(wx.EVT_TEXT, self.onSelectElementEdit)
    self.listPanelWidgets.append(self.selectElementEdit)

    # ADD ELEMENT
    #     adds the selected element
    #     Disabled when all possible elements exist
    #     sets corresponding IncludeXXX to TRUE
    #
    self.addElementButton = wx.Button( self.listPanel, -1, label="Add    Element")
    self.listPanelSizer.Add( self.addElementButton, pos=(2,0))
    self.listPanelWidgets.append(self.addElementButton)
    self.addElementButton.Bind(wx.EVT_BUTTON, self.onAddElementClick)

    self.addElementChoicesPs = []
    self.addElementChoicesPs += DEFINES.ELEMENT
    self.addElementChoicesPo = []
    self.addElementChoicesPo += DEFINES.ELEMENT_PO_RULES

    # DELETE ELEMENT combo
    #     Deletes the selected element
    #     Disabled when NumberOfElements = 0
    #     sets corresponding IncludeXXX to FALSE
    #
    self.deleteElementButton = wx.Button( self.listPanel, -1, label="Delete Element")
    self.deleteElementButton.Enable( False )
    self.listPanelSizer.Add( self.deleteElementButton, pos=(3,0))
    self.listPanelWidgets.append(self.deleteElementButton)
    self.deleteElementButton.Bind(wx.EVT_BUTTON, self.onDeleteElementButtonClick)

    # Revocation Count text box - PDEF.PolList[n]ListVersion.RevocationCounter
    #     updated automatically each time the user performs a BUID, but only if the list is signed
    self.revocationCountLabel = wx.StaticText(self.listPanel, label="Revocation\nCount: ")
    self.listPanelSizer.Add( self.revocationCountLabel, pos=(2,6))
    self.listPanelWidgets.append(self.revocationCountLabel)
    self.revocationCountEdit  = wx.TextCtrl( self.listPanel, value="0", size=(30, -1))
    self.revocationCountEdit.Enable(False)                  # disable editing since updated automatically on BUILD's
    self.listPanelSizer.Add( self.revocationCountEdit,  pos=(2,7))
    self.listPanelWidgets.append(self.revocationCountEdit)

    # Allowed text box - PDEF.PolList[n]ListVersion.RevokeCount
    #     permits user to enter a value between 0 and RevocationCounter
    #     Copied to PDEF.RevocationCounters[n] when policy is built
    self.allowedLabel = wx.StaticText(self.listPanel, label="Allowed")
    self.listPanelSizer.Add( self.allowedLabel, pos=(3,6))
    self.listPanelWidgets.append(self.allowedLabel)
    self.allowedEdit  = wx.TextCtrl( self.listPanel, value="0", size=(30, -1))
    self.allowedEdit.Enable(False)                       # disabled since Sync checkbox defaults to True
    self.listPanelSizer.Add( self.allowedEdit,  pos=(3,7))
    self.listPanelWidgets.append(self.allowedEdit)
    self.allowedEdit.Bind(wx.EVT_TEXT, self.onAllowedEdit)

    # Reset button
    #     Resets the Revocation Count to 0
    #
    self.resetButton = wx.Button( self.listPanel, -1, label="Reset", style=wx.BU_EXACTFIT)
    self.resetButton.Enable(False)
    self.listPanelSizer.Add( self.resetButton, pos=(4,6))
    self.listPanelWidgets.append(self.resetButton)
    self.resetButton.Bind(wx.EVT_BUTTON, self.onResetButtonClick)

    # Sync checkbox - PDEF.PolListInfo[n].SyncRevCount
    #      if checked, force Allowed to equal Revocation Count and Allowed box is disabled
    #
    self.Sync = wx.CheckBox(self.listPanel, label="Sync")
    self.Sync.SetValue(True)
    self.Sync.Bind(wx.EVT_CHECKBOX, self.onSync)
    self.listPanelSizer.Add(self.Sync,  pos=(4,7), span=(1,2), flag=wx.BOTTOM, border=5)
    self.listPanelWidgets.append(self.Sync)

    # Private Key File text box - PDEF.PolList[n].PvtKeyFile
    #     allows user to specify the file that contains the signing key
    self.pvtKeyFileSel = wx.ComboBox( self.listPanel, size=(80, -1), value="Private Key", choices=["Private Key", "Signature"], style=wx.CB_READONLY )
    self.pvtKeyFileSel.Bind(wx.EVT_TEXT, self.onPvtKeyFileSel)
    self.listPanelSizer.Add( self.pvtKeyFileSel, pos=(2,11))
    self.listPanelWidgets.append(self.pvtKeyFileSel)

    self.pvtKeyFileEdit  = wx.TextCtrl( self.listPanel, value="", size=(110, -1))
    self.pvtKeyFileEdit.Bind(wx.EVT_TEXT, self.onPvtKeyFileEdit)
    self.listPanelSizer.Add( self.pvtKeyFileEdit,  pos=(2,12))
    self.listPanelWidgets.append(self.pvtKeyFileEdit)

    # BROWSE button
    #     bring up a File Browse dialogue
    #
    self.pvtBrowseButton = wx.Button( self.listPanel, -1, label="Browse", style=wx.BU_EXACTFIT)
    self.listPanelSizer.Add( self.pvtBrowseButton, pos=(2,13))
    self.listPanelWidgets.append(self.pvtBrowseButton)
    self.pvtBrowseButton.Bind(wx.EVT_BUTTON, self.onPvtBrowseButtonClick, self.pvtBrowseButton)

    # Key File text box - PDEF.PolList[n].PubKeyFile
    #     allows user to specify the file that contains the signing key
    self.pubKeyFileLabel = wx.StaticText(self.listPanel, label="Public Key")
    #font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    #self.pubKeyFileLabel.SetFont( font )
    self.listPanelSizer.Add( self.pubKeyFileLabel, pos=(3,11))
    self.listPanelWidgets.append(self.pubKeyFileLabel)

    self.pubKeyFileEdit  = wx.TextCtrl( self.listPanel, value="", size=(110, -1))
    self.pubKeyFileEdit.Bind(wx.EVT_TEXT, self.onPubKeyFileEdit)
    self.listPanelSizer.Add( self.pubKeyFileEdit,  pos=(3,12))
    self.listPanelWidgets.append(self.pubKeyFileEdit)

    # BROWSE button
    #     bring up a File Browse dialogue
    #
    self.pubBrowseButton = wx.Button( self.listPanel, -1, label="Browse", style=wx.BU_EXACTFIT)
    self.listPanelSizer.Add( self.pubBrowseButton, pos=(3,13))
    self.listPanelWidgets.append(self.pubBrowseButton)
    self.pubBrowseButton.Bind(wx.EVT_BUTTON, self.onPubBrowseButtonClick)

    # Key Size Control - PDEF.PolList[n].KeySize
    #     Allows user to select one of the supported key sizes: 1024, 2048, 3072
    #
    self.keySizeList = DEFINES.SIGNATURE_KEY_SIZE["RSA PKCS1.5/SHA256"]
    self.keySizeLabel = wx.StaticText(self.listPanel, label="Key Size")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    self.keySizeLabel.SetFont( font )
    self.listPanelSizer.Add(self.keySizeLabel, pos=(2,10))
    self.listPanelWidgets.append(self.keySizeLabel)

    self.keySizeEdit = wx.ComboBox( self.listPanel, size=(110, -1), value="2048", choices=self.keySizeList, style=wx.CB_READONLY )
    self.keySizeEdit.Bind(wx.EVT_TEXT, self.onKeySizeEdit)
    self.listPanelSizer.Add(self.keySizeEdit, pos=(3,10))
    self.listPanelWidgets.append(self.keySizeEdit)

    # AlgorithmControl - PDEF.PolList[n].SigAlgorithm
    #     Allows user to select supported algorithms, but only RSA PKCS1.5
    #
    self.algorithmList = DEFINES.SIGNATURE_ALGORITHMS
    self.algorithmLabel = wx.StaticText(self.listPanel, label="Signing\nAlgorithm ")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.algorithmLabel.SetFont( font )
    self.listPanelSizer.Add(self.algorithmLabel, pos=(1,11))
    self.listPanelWidgets.append(self.algorithmLabel)

    self.algorithmEdit = wx.ComboBox( self.listPanel, size=(165, -1), value="None", choices=self.algorithmList, style=wx.CB_READONLY )
    self.algorithmEdit.Bind(wx.EVT_TEXT, self.onAlgorithmEdit)
    self.listPanelSizer.Add(self.algorithmEdit, pos=(1,12), span=(1,2))
    self.listPanelWidgets.append(self.algorithmEdit)
    self.enableDisableSigned(False)                     # default to not signed

    #listHorizSizer.Add(listGridSizer,  0, wx.ALL, 5)
    #self.listPanelSizer.Add(listHorizSizer, 0, wx.ALL, 5)
    #parent.Add(listHorizSizer)
    parentSizer.Add(self.listPanel)
    w,h = parentSizer.GetMinSize()
    parent.SetVirtualSize((w,h))
    print("parent sizer type = %s  size = %d, %d" %(type(parentSizer).__name__, w, h))
    #parent.Fit()
    parent.Layout()
    #parent.SetSizerAndFit(self.listPanelSizer)

  def hideListPanel(self):
    """hideListPanel - remove [actually just hide] the list panel and any element panels from the policy panel"""

    for i in self.listPanelWidgets:
        i.Hide()

    self.hideAllPanels()     # hide all the panels

    #TODO: wxPython: hideListPanel - how to resize window back to the original Policy Panel size when delting a list?

  def showListPanel(self):
    """showListPanel - re-show the list and element panels"""

    #print("in showListPanel listPanelWidgets=%s" % (self.listPanelWidgets))   # DBGDBG
    for i in self.listPanelWidgets:
        i.Show()

    for element in self.includedElements:
      element.showPanel()

    parentSizer = self.parent.GetSizer()
    w,h = parentSizer.GetMinSize()
    self.parent.SetVirtualSize((w,h))


  def setListPanelToDefaults(self, wx, parent, listNumber, pdef):
    """setListPanelToDefaults - widgets were all ready created, restore defaults"""
    #self.StatusBar.SetStatusText("Created LIST %i with default values" % (listNumber))
    print("Created LIST %i with default values" % (listNumber))

    self.listLabelNum.ChangeValue(str(listNumber))
    policyversion = str(pdef.PolVersionMajor)+'.'+str(pdef.PolVersionMinor)
    listversion = DEFINES.SUPPORTED_LCP_VERSION[policyversion]
    self.versionEdit.ChangeValue(listversion)
    self.numberElementsEdit.ChangeValue("0")
    self.selectElementEdit.Clear()
    self.selectElementEdit.Append('None')
    self.selectElementEdit.SetSelection(0)
    self.addElementChoicesPs = []
    self.addElementChoicesPs += DEFINES.ELEMENT
    self.addElementChoicesPo = []
    self.addElementChoicesPo += DEFINES.ELEMENT_PO_RULES
    self.revocationCountLabel.Enable(True)
    self.revocationCountEdit.ChangeValue("0")
    self.allowedLabel.Enable(True)
    self.allowedEdit.ChangeValue("0")
    self.resetButton.Enable(True)
    self.Sync.SetValue(True)
    self.Sync.Enable(True)
    self.algorithmEdit.SetValue("None")
    self.pubKeyFileEdit.ChangeValue("")
    self.pubKeyFileEdit.Enable(False)
    self.pvtKeyFileEdit.ChangeValue("")
    self.pvtKeyFileEdit.Enable(False)
    self.pubBrowseButton.Enable(False)
    self.pvtBrowseButton.Enable(False)
    self.keySizeEdit.SetValue("2048")
    self.keySizeEdit.Enable(False)
    self.algorithmEdit.Enable(True)

    for i in self.listPanelWidgets:
        i.Show()

    for elements in self.includedElements:
      elements.hidePanel()

    # delete element GUI panels in self.includedElements[] and elements in pdef.CurrentList.ElementDefData[]
    self.includedElements = []
    currentListObject = pdef.getCurrentListObject()
    currentListObject.ElementDefData = []


  def restoreListPanel(self, currentList):
    """restoreListPanel - restore the list panel's widgets"""
    func = 'restoreListPanel'

    self.hideAllPanels()
    self.listLabelNum.ChangeValue(str(self.pdef.CurrentListView))
    cnt = 0
    self.rebuildSelectElementChoices()
    self.addElementChoicesPs = []
    self.addElementChoicesPs += DEFINES.ELEMENT           # copy elements not just reference
    self.addElementChoicesPo = []
    self.addElementChoicesPo += DEFINES.ELEMENT_PO_RULES  # copy elements not just reference

    cnt = len(currentList.ElementDefData)
    #self.numberElementsEdit.ChangeValue(str(cnt))

    if(cnt > 0):
      flag = True
      self.selectElementEdit.SetValue(currentList.CurrentElementView)
      #self.selectElementEdit.SetSelection(cnt)
    else:
      flag = False
      currentList.CurrentElementView  = DEFINES.ELEMENT_NAME_NONE
      #self.visibleElement = DEFINES.ELEMENT_NAME_NONE
      self.selectElementEdit.SetValue(DEFINES.ELEMENT_NAME_NONE)
      self.selectElementEdit.SetSelection(0)

    # show element panel for selected element
    selection = self.selectElementEdit.GetSelection()
    if selection > 0:
      self.includedElements[selection-1].showPanel()
      self.selectElementEdit.Enable(flag)
      self.deleteElementButton.Enable(flag)

    #print("restoreListPanel - Sync=%s SigAlgorithm=%x" % (currentList.SyncRevCount, currentList.SigAlgorithm))  # DBGDBG
    self.Sync.SetValue(currentList.SyncRevCount)
    self.allowedEdit.ChangeValue(str(currentList.RevokeCounter))
    self.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))
    self.keySizeEdit.SetValue(str(currentList.KeySize))
    #if (currentList.SigAlgorithm == 1):  # For TPM 1.2

    signAlgName = ""
    try:
      signAlgName = (key for key,val in DEFINES.TPM_ALG_SIGN.items() if currentList.SigAlgorithm == val).next()
    except StopIteration:
      print("WARNING - Invalid signature algorithm (%d)" %(currentList.SigAlgorithm))

    hashAlgName = ""
    try:
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if currentList.sigAlgorithmHash == val).next()
    except StopIteration:
      print("WARNING - Invalid hash algorithm (%d)" %(currentList.sigAlgorithmHash))

    selectionString = "None"
    if 'RSA' in signAlgName:
      selectionString = (name for name in DEFINES.SIGNATURE_ALGORITHMS if 'RSA' in name and hashAlgName in name).next()
      enable = True
    elif 'ECDSA' in signAlgName:
      selectionString = (name for name in DEFINES.SIGNATURE_ALGORITHMS if signAlgName in name and currentList.KeySize in name).next()
      enable = True
    #elif 'SM2' in signAlgName:
    #  selectionString = (name for name in DEFINES.SIGNATURE_ALGORITHMS if signAlgName in name).next()
    #  enable = True
    else:
      enable = False

    self.enableDisableSigned(enable, selectionString)
    self.algorithmEdit.SetValue(selectionString)
    self.pvtKeyFileSel.SetSelection(currentList.PvtKeyFileIsSignature)
    self.pubKeyFileEdit.ChangeValue(currentList.PubKeyFile)
    self.pvtKeyFileEdit.ChangeValue(currentList.PvtKeyFile)
    #currentList.ListModified = False # don't want to change the state of this variable

  def setListPanelToCurrentListView(self):
    """setListPanelToCurrentListView - update the list panel to the specified list"""

    currentList = self.pdef.getCurrentListObject()
    print("setListPanelToCurrentListView %i AllowedCounter=%i" % (self.pdef.CurrentListView, currentList.RevokeCounter)) # DBGDBG

    # Hide all panels before rebuilding the list for the new panel
    self.hideAllPanels()
    # Clear GUI panels for each element
    self.includedElements = []

    # Re-build the GUI panel for each element from the PDEF persistent object in pdef.py file
    index = 0
    for defdata in currentList.ElementDefData:
      # Get Name and Hash type of each and recreate GUI element with it.

      # Create a new element of selected spec and populate into currentListObject.MleDefData
      elementType, hashAlg = defdata.Name.split('-')

      if hashAlg == 'LEGACY':
        if elementType == 'SBIOS':
          element = SBIOSLegacy()
        elif elementType == 'MLE':
          element = MLELegacy()
        elif elementType == 'PCONF':
          element = PCONFLegacy()
        else:
          print ("ERROR: invalid element")
      else:
        if elementType == 'SBIOS':
          element = SBIOS(DEFINES.TPM_ALG_HASH[hashAlg])      # GUI panel
        elif elementType == 'STM':
          element = STM(DEFINES.TPM_ALG_HASH[hashAlg])
        elif elementType == 'MLE':
          element = MLE(DEFINES.TPM_ALG_HASH[hashAlg])
        elif elementType == 'PCONF':
          element = PCONF(DEFINES.TPM_ALG_HASH[hashAlg])
        else:
          print ("ERROR: invalid element")

      element.createOrShowPanel(wx, self, self.parent, self.pdef, self.StatusBar)
      element.myIndex = index
      self.includedElements.append(element)
      element.restorePanel(currentList, self.pdef.MaxHashes)
      element.hidePanel()
      index += 1

    # restore any element panels that exist in the current PLIST_DEF

    # Also update this list's element panel, if one exists
    # 1st hide all the  elements and enable if they don't exist and rules allow that
    #self.hideAllPanels()    # Hide all the element panels

    # then disable add buttons for elements that exist
    # and count the number of elements in this list
    numberOfElements = len(currentList.ElementDefData)

    # rebuild selectElementEdit's choices list for the elements existing in this view
    self.rebuildSelectElementChoices()

    # then show a panel

    # update the NumberOfElements and enable selectElementsEdit if > 0
    self.numberElementsEdit.ChangeValue(str(numberOfElements))
    if(numberOfElements > 0):
        self.selectElementEdit.Enable( True )
        self.deleteElementButton.Enable( True )

    self.restoreListPanel(currentList)


  # only called if PolicyType = LIST if pdef.NumLists > 0
  # for each signed list,
  #   If Sync is checked,
  #     then update the current list's AllowedCounter from its RevocationCounter
  #   update pdef.DataRevocationCounters[list#] from the current list's Allowedounter
  #   if the current List is displayed in the list panel, update the list panel widgets
  #
  # NOTE: the current list's RevocationCounter is incr on its 1st modification
  #
  def onBuildButtonClick(self, pdef):
    """ onBuildButtonClick - perform a build"""
    #print("list::onBuildButtonClick")   # DBGDBG

    listNum = 0
    while( listNum < pdef.NumLists):
      thisList = pdef.PolListInfo[str(listNum)]
      #if(thisList.SigAlgorithm == DEFINES.LCP_POLSALG_RSA_PKCS_15):  # For TPM1.2
      if(thisList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']):
        if(thisList.SyncRevCount == True):
          thisList.RevokeCounter = thisList.RevocationCounter

        pdef.DataRevocationCounters[listNum] = thisList.RevokeCounter

        # is this list being shown in the list panel?
        if(pdef.CurrentListView == listNum + 1):
          self.allowedEdit.ChangeValue(str(thisList.RevokeCounter))
          self.revocationCountEdit.ChangeValue(str(thisList.RevocationCounter))

        if(thisList.RevocationCounter > 0):       # can't reset til cnt > 0
            self.resetButton.Enable(True)

        print("list.onBuild - list %d, RevCnt=%d, RevokeCnt=%d, pdef.DataRevocationCounters[%d]=%d" %
          (listNum+1, thisList.RevocationCounter, thisList.RevokeCounter, listNum+1, pdef.DataRevocationCounters[listNum]))    # DBGDBG

      listNum += 1

    #print("list.onBuild - pdef.DataRevocationCounters=%s" % (pdef.DataRevocationCounters)) # DBGDBG

  def onAllowedEdit(self, event):
    """ onAllowedEdit - handle Allowed value change"""

    string = event.GetString()
    self.StatusBar.SetStatusText("in onAllowedEdit, value=%s" % (string))

    currentList = self.pdef.getCurrentListObject()
    maxValue = currentList.RevocationCounter
    #print("onAllowedEdit - MaxValue=%i" % (maxValue))  # DBGDBG

    try:
      value = int(string)
    except:
      self.StatusBar.SetStatusText(  "%s is invalid, Please enter only digits between 0 and %i" % (string, maxValue))
    else:
      #print("onAllowedEdit - Value=%i" % (value))  # DBGDBG
      if(value > maxValue):
        self.allowedEdit.ChangeValue(str(currentList.RevokeCounter))
        self.StatusBar.SetStatusText( "%i is too large, the max value for Allowed is %i" % ( value, maxValue ))
      else:
        currentList.RevokeCounter = value
        print("onAllowedEdit - setting RevokeCounter=%i MaxValue=%i" % (value, maxValue))
        self.setListModified()

  def onSelectElementEdit(self, event):
    """onSelectElementEdit - view the selected element"""
    func = 'onSelectElementEdit'

    #selection = self.selectElementEdit.GetSelection()
    selection = event.GetEventObject().GetSelection()
    selectionString = event.GetString()
    #self.setListModified()   # just looking at different element shouldn't be considered modifying it.
    #Element = DEFINES.ELEMENT
    #Object  = self.getObject()
    currentList = self.pdef.getCurrentListObject()
    #IncludeElement = utilities.getIncludeElement(currentList)

    # Using exhaustive find method to match selected element by it's element name and hash alg
    #for element in self.includedElements:
    #  found = element.isElementType(selectionString)
    #  if found:
    #    self.StatusBar.SetStatusText( "Displaying the %s element" % (selectionString))
    #    self.hideAllPanels()
    #    element.showPanel()
    #    self.visibleElement = selectionString
    #    currentList.CurrentElementView = selectionString
    #    break

    if(selectionString == DEFINES.ELEMENT_NAME_NONE):
      self.StatusBar.SetStatusText( "No element selected")
      self.visibleElement = selectionString
      currentList.CurrentElementView = selectionString
      self.hideAllPanels()
    else:
      self.StatusBar.SetStatusText( "Displaying the %s element" % (selectionString))
      self.hideAllPanels()
      self.includedElements[selection-1].showPanel()
      self.visibleElement = selectionString
      currentList.CurrentElementView = selectionString


    #TODO: wxPython: onSelectElementEdit - how to resize panel here?  Or set min size after each panel is created?
    print("%s: selection=%d, visibleElement=%s" % (func, self.selectElementEdit.GetSelection(), self.visibleElement)) # DBGDBG)

  def onDeleteElementButtonClick(self, event):
    """ onDeleteElementButtonClick - delete the current element"""
    func = 'onDeleteElementButtonClick'
    self.StatusBar.SetStatusText( "Deleted the current element")

    #exit if None is selected, else confirm the deletion and continue
    if(self.visibleElement == DEFINES.ELEMENT_NAME_NONE):
      self.StatusBar.SetStatusText( "No element selected, Please select the element to be deleted")
      return

    # confirm delete
    dlg = wx.MessageDialog(None, "Deleted Elements cannot be recovered. Continue?", 'Confirm Element Deletion', wx.YES_NO | wx.ICON_QUESTION)
    response = dlg.ShowModal()
    dlg.Destroy()

    if(response == wx.ID_NO):
      self.StatusBar.SetStatusText( "Element Deletion cancelled" )
      return
    else:
      self.StatusBar.SetStatusText( "Element deleted")

    # ComboBox selection value is one index higher than self.includedElement[] index and PLIST_DEF.ElementDefData[] index
    # because of the None element to select no view.
    selection = self.selectElementEdit.GetSelection()             # get the index
    selectionString = self.selectElementEdit.GetValue()           # get selected element and populate into Add Element menu
    self.selectElementEdit.Delete(selection)
    print("%s - Selection=%d VisibleElement=%s - Removed" % (func, selection, self.visibleElement)) # DBGDBG

    currentElementsCnt = int(self.numberElementsEdit.GetValue())
    if(selection > 0):
      nextselection = selection - 1
      # fixup selection for out of order case where selection 1 was deleted, but are > 1 elements left
      # ie should only select 0 if 0 elements left  ie None is the only choice left
      # Scenario:  create > 1 elements, select 1, delete 1. 1 still selected
      if((nextselection == 0) and (currentElementsCnt > 1)):
        nextselection = 1
      self.selectElementEdit.SetSelection(nextselection)
    else:
      print("%s: selectElementEdit.GetSelection() is invalid, Aborting!! % (func)")
      return

    # set IncludeXXX to False
    # hide the current element, show another element if one exists
    self.setListModified()
    #self.dumpIncludeXXX( currentListObject, 'before delete' )      # show current value of all the  XXXDefData[i].IncludeXXXX  # DBGDBG

    # Add deleted element back to Add Element menu.
    self.updateAddElementChoicesAfterDelete(selectionString)

    # update myIndex of the elements behind this element
    for count in range(selection, len(self.includedElements)):
      self.includedElements[count].myIndex -= 1

    # remove item from pdef list
    currentListObject = self.pdef.getCurrentListObject()
    currentListObject.ElementDefData.pop(selection-1)

    # update GUI to show other element
    if selection > 0:
      self.includedElements[selection-1].hidePanel()
      # remove this element's GUI
      self.includedElements.pop(selection-1)

    # nextselection is indexing into the updated self.includedElements[]
    if nextselection != 0:
      self.includedElements[nextselection-1].showPanel()

    # Set other GUI fields
    currentElementsCnt -= 1
    self.numberElementsEdit.ChangeValue(str(currentElementsCnt))
    if(currentElementsCnt > 0):
      self.selectElementEdit.Enable( True )
      self.addElementButton.Enable(True)
      self.visibleElement = self.selectElementEdit.GetValue()
      currentListObject.CurrentElementView = self.selectElementEdit.GetValue()
      print("%s - Selection=%d VisibleElement=%s" % (func, selection, self.visibleElement)) # DBGDBG
    elif(currentElementsCnt == 0):
      self.selectElementEdit.Enable( False )
      self.deleteElementButton.Enable( False )
      self.visibleElement = DEFINES.ELEMENT_NAME_NONE
      currentListObject.CurrentElementView = DEFINES.ELEMENT_NAME_NONE

    #self.dumpIncludeXXX( currentListObject, 'after delete' )      # show current value of all the  XXXDefData[i].IncludeXXXX  # DBGDBG

  # Object - array of all the mle, sbios, pconf & stm 1 and 256 objects
  # Element - array of all the ELEMENT_NAME_XXXX_SHAYYY strings
  # IncludeElement - array of all the XXXXDefData[DEFINES.DEFDATA_INDEX_SHANNN.IncludeXXXX
  #         updated to indicate the just deleted element's value is now False
  #
  def showNextElement(self, Object, Element, IncludeElement, currentListObject):
    """showNextElement - if another element's panel exists, show it"""
    func = 'showNextElement'

    i=0
    while(i < len(Element)):
      #print("%s - checking %s" % (func, Element[i]))  # DBGDBG
      if(IncludeElement[i] == True):
        print("%s - showing %s" % (func, Element[i]))  # DBGDBG
        Object[i].showPanel()
        self.visibleElement = Element[i]
        currentListObject.CurrentElementView = Element[i]
        self.selectElementEdit.SetValue(Element[i])
        break

      i += 1      # next element


  def onResetButtonClick(self, event):
    """ onResetButtonClick - reset the revocation count"""
    self.StatusBar.SetStatusText( "You clicked the Reset Button!")

    if(self.revocationCountEdit.GetValue() != "0"):
      dlg = wx.MessageDialog(None, "Revocation Count reset cannot be undone. Continue?", 'Confirm Revocation Count reset', wx.YES_NO | wx.ICON_QUESTION)
      response = dlg.ShowModal()
      dlg.Destroy()

      if(response == wx.ID_NO):
        self.StatusBar.SetStatusText( "Revocation Count reset cancelled" )
      else:
        self.StatusBar.SetStatusText( "Reset the Revocation Count " )
        self.revocationCountEdit.ChangeValue("0")
        currentList = self.pdef.getCurrentListObject()
        currentList.RevocationCounter = 0
        #self.setListModified()         # don't set list modified here as that re-increments the revocation ctr
        self.resetButton.Enable(False)

  def onSync(self, event):
    """ onSync - force Allowed to equal Revocation Count and disable Allowed"""

    self.StatusBar.SetStatusText("You checked Sync")
    currentList = self.pdef.getCurrentListObject()
    if(event.IsChecked()):
      self.allowedEdit.ChangeValue(self.revocationCountEdit.GetValue())
      currentList.SyncRevCount = True
      currentList.RevokeCounter = currentList.RevocationCounter
      self.setListModified()
      print("onSync - PolList[%i].RevCnt=%i, Allowed=%i" %
        (self.pdef.CurrentListView, currentList.RevokeCounter, currentList.RevocationCounter))    # DBGDBG
    else:
      currentList.SyncRevCount = False

    # when checked disable editing the allowed box
    self.allowedEdit.Enable(not event.IsChecked())

  def enableDisableSigned(self, value, signAlgName='None'):
    """enableDiableSigned - perform common actions when Signed or Algorithm changed"""

    # Note: Sync checkbox and Algorithm pulldown are redundant
    #   Sync unchecked  == LCP_POLSALG_NONE
    #   Sync checked    == LCP_POLSALG_RSA_PKCS_15

    #If Unsigned [ie algorithm=None], then revocation count, allowed, RESET, Sync, Key File & Key Size are all disabled,
    # else enabled

    currentList = self.pdef.getCurrentListObject()
    keysizeList = DEFINES.SIGNATURE_KEY_SIZE[signAlgName]

    if(value == False):
      #value = False
      self.allowedEdit.Enable(value)
      #currentList.SigAlgorithm = DEFINES.TPM_ALG_SIGN['NULL']       # 0=Not signed
      #self.algorithmEdit.SetValue(DEFINES.ELEMENT_NAME_NONE)
    else:
      #value = True
      self.allowedEdit.Enable(not value)

    self.setListModified()
    self.resetButton.Enable(value)
    self.Sync.Enable(value)
    self.pubKeyFileEdit.Enable(value)
    self.pvtKeyFileEdit.Enable(value)
    self.pubBrowseButton.Enable(value)
    self.pvtBrowseButton.Enable(value)
    self.keySizeEdit.SetItems(keysizeList)
    self.keySizeEdit.SetValue(str(currentList.KeySize))
    self.keySizeEdit.Enable(value)
    self.revocationCountLabel.Enable(value)
    self.allowedLabel.Enable(value)
    self.pvtKeyFileSel.Enable(value)
    self.pubKeyFileLabel.Enable(value)
    self.keySizeLabel.Enable(value)

  def onPubKeyFileEdit(self, event):
    """ onpubKeyFileEdit - update the key file"""

    currentList = self.pdef.getCurrentListObject()
    currentList.PubKeyFile = event.GetString()
    self.setListModified()

    # once the entire file name is entered, verify it, else clear it
    if(currentList.PubKeyFile.endswith(".pem")):
      if currentList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']:
        type = DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']
      elif currentList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['ECDSA']:
        type = DEFINES.KEY_FILE_TYPE['PUBLIC_ECDSA']

      if(utilities.verifyKeyFile(currentList.PubKeyFile, type, currentList) == False):
        self.pubKeyFileEdit.ChangeValue("")

  def onPvtKeyFileSel(self, event):
    """ onPvtKeyFileEdit - update the key file"""
    currentList = self.pdef.getCurrentListObject()
    selectionString = event.GetString()
    if selectionString == "Private Key":
      currentList.PvtKeyFileIsSignature = False
    else:
      currentList.PvtKeyFileIsSignature = True


  def onPvtKeyFileEdit(self, event):
    """ onPvtKeyFileEdit - update the key file"""

    currentList = self.pdef.getCurrentListObject()
    currentList.PvtKeyFile = event.GetString()
    self.setListModified()

    # once the entire file name is entered, verify it, else clear it
    if((currentList.PvtKeyFile.endswith(".pem")) or (currentList.PvtKeyFile.endswith(".key"))):
      if(utilities.verifyKeyFile(currentList.PvtKeyFile, KEY_FILE_TYPE_PRIVATE, currentList) == False):
        self.pvtKeyFileEdit.ChangeValue("")

  def onKeySizeEdit(self, event):
    """ onKeySizeEdit - update the key size"""

    currentList = self.pdef.getCurrentListObject()
    currentList.KeySize = event.GetString()
    self.setListModified()
    self.StatusBar.SetStatusText("")   # clear any previous error messages

    #if key file was all rdy specified, verify its size is correct
    file = self.pubKeyFileEdit.GetValue()
    if(file != ""):
      if(utilities.verifyKeyFile(file, KEY_FILE_TYPE_PUBLIC, currentList) == False):
        self.pubKeyFileEdit.ChangeValue("")
        currentList.PubKeyFile = ""

    file = self.pvtKeyFileEdit.GetValue()
    if(file != ""):
      if(utilities.verifyKeyFile(file, KEY_FILE_TYPE_PRIVATE, currentList) == False):
        self.pvtKeyFileEdit.ChangeValue("")
        currentList.PvtKeyFile = ""

  def onPvtBrowseButtonClick(self, event):
    """ onPvtBrowseButtonClick - browse to an existing PDEF file"""

    #self.StatusBar.SetStatusText("You clicked the Browse button")
    #TODO: Bill: handle .pems that have both the public and private keys?
    #TODO: Bill: handle .pems with password protected private keys?

    currentList = self.pdef.getCurrentListObject()
    #accept .key as well as pem files for private keys?
    dirname = ''   #  current working directory
    workdir = self.pdef.WorkingDirectory

    if currentList.PvtKeyFileIsSignature:
      title = "Choose the Signature file"
      wildcard = "All Files (*.*)|*.*|" \
                 "Key file (*.sig)|*.sig|"
    else:
      title = "Choose the Private Key file"
      wildcard = "Key file (*.pem)|*.pem|" \
                 "Key file (*.key)|*.key|" \
                 "All Files (*.*)|*.*"
    dlg = wx.FileDialog(self.parent, title, workdir, "", wildcard, wx.FD_OPEN)

    if dlg.ShowModal() == wx.ID_OK:
      filename = dlg.GetFilename()
      dirname  = dlg.GetDirectory()

      self.pvtKeyFileEdit.ChangeValue(filename)
      currentList.PvtKeyFile = filename
      self.setListModified()

      if currentList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']:
        filetype = DEFINES.KEY_FILE_TYPE['PRIVATE_RSASSA']
      else:
        filetype = DEFINES.KEY_FILE_TYPE['PRIVATE_ECDSA']

      if currentList.PvtKeyFileIsSignature:
        #copy signature file to the current working directory
        pass
      else:
      # Verify Private Key file
        if(utilities.verifyKeyFile(os.path.join(dirname, currentList.PvtKeyFile), filetype, currentList) == False):
          self.pvtKeyFileEdit.ChangeValue("")
          currentList.PvtKeyFile = ""
        elif (dirname != workdir):
          if (os.path.exists(os.path.join(workdir, filename))) :
            confdlg = wx.MessageDialog(self.parent, filename+" already exists in working directory\nOverwrite file in working directory?", "Confirm Copy", wx.OK|wx.CANCEL|wx.ICON_QUESTION)
            abortFlag = False
            if (confdlg.ShowModal() == wx.ID_OK):
              shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))
            else:
              abortFlag = True

            confdlg.Destroy()
            if(abortFlag == True):
              if(utilities.verifyKeyFile(os.path.join(workdir, currentList.PvtKeyFile), filetype, currentList) == False):
                # don't change
                self.pvtKeyFileEdit.ChangeValue("")
                currentList.PvtKeyFile = ""
              self.StatusBar.SetStatusText( "Copy cancelled, using exiting key" )
          else:
            shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))

    dlg.Destroy()
    #print("onPvtBrowseButtonClick: %s" % (currentList.PvtKeyFile))   # DBGDBG

  def onPubBrowseButtonClick(self, event):
    """ onPubBrowseButtonClick - browse to an existing PDEF file"""

    #self.StatusBar.SetStatusText("You clicked the Browse button")
    dirname = ''   #  current working directory
    workdir = self.pdef.WorkingDirectory
    wildcard = "Key file (*.pem)|*.pem|" \
               "All Files (*.*)| *.*"
    dlg = wx.FileDialog(self.parent, "Choose the Public Key file", workdir, "", wildcard, wx.FD_OPEN)

    currentList = self.pdef.getCurrentListObject()
    if currentList.SigAlgorithm == DEFINES.TPM_ALG_SIGN['RSASSA']:
      filetype = DEFINES.KEY_FILE_TYPE['PUBLIC_RSASSA']
    else:
      # treat SM2 as ECDSA key
      filetype = DEFINES.KEY_FILE_TYPE['PUBLIC_ECDSA']

    if dlg.ShowModal() == wx.ID_OK:
      filename = dlg.GetFilename()
      dirname  = dlg.GetDirectory()

      self.pubKeyFileEdit.ChangeValue(filename)
      currentList.PubKeyFile = filename
      self.setListModified()
      if(utilities.verifyKeyFile(os.path.join(dirname, currentList.PubKeyFile), filetype, currentList) == False):
        self.pubKeyFileEdit.ChangeValue("")
        currentList.PubKeyFile = ""
      elif (dirname != workdir):
        if (os.path.exists(os.path.join(workdir, filename))) :
          confdlg = wx.MessageDialog(self.parent, filename+" already exists in working directory\nOverwrite file in working directory?", "Confirm Copy", wx.OK|wx.CANCEL|wx.ICON_QUESTION)
          abortFlag = False
          if (confdlg.ShowModal() == wx.ID_OK):
            shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))
          else:
            abortFlag = True

          confdlg.Destroy()
          if(abortFlag == True):
            # verify the existing file
            if(utilities.verifyKeyFile(os.path.join(workdir, currentList.PubKeyFile), filetype, currentList) == False):
              self.pubKeyFileEdit.ChangeValue("")
              currentList.PubKeyFile = ""
            self.StatusBar.SetStatusText( "Copy cancelled, using exiting key" )
        else:
          shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))

    dlg.Destroy()
    #print("onPubBrowseButtonClick: %s" % (currentList.PubKeyFile))   # DBGDBG

  def onAlgorithmEdit(self, event):
    """ onAlgorithmEdit - select the algorithm"""

    func = "onAlgorithmEdit"
    currentList = self.pdef.getCurrentListObject()
    selectionString = event.GetString()
    algName = selectionString.split('/')
    if len(algName) == 2:
      sigAlg = algName[0].split(' ')[0]
      hashAlg = algName[1]

      # Check for valid signature algorithm name
      try:
        sigAlgName = (key for key in DEFINES.TPM_ALG_SIGN.keys() if (sigAlg in key)).next()
      except StopIteration:
        self.StatusBar.SetStatusText("Signature algorithm name mismatch")
        print("%s - Signature algorithm name mismatch" % (func))  # DBGDBG
        return

      # Check for valid algorithm name
      try:
        hashAlgName = (key for key in DEFINES.TPM_ALG_HASH.keys() if (hashAlg in key)).next()
      except StopIteration:
        self.StatusBar.SetStatusText("Hash algotithm name mismatch")
        print("%s - Hash algorithm name mismatch" % (func))  # DBGDBG
        return

      currentList.SigAlgorithm = DEFINES.TPM_ALG_SIGN[sigAlgName]
      currentList.sigAlgorithmHash = DEFINES.TPM_ALG_HASH[hashAlgName]
      if currentList.KeySize not in DEFINES.SIGNATURE_KEY_SIZE[selectionString]:
        currentList.KeySize = DEFINES.SIGNATURE_KEY_SIZE[selectionString][0]
      self.enableDisableSigned(True, selectionString)
    else:
      currentList.SigAlgorithm = DEFINES.TPM_ALG_SIGN['NULL']
      self.enableDisableSigned(False)


  def onAddElementClick(self, event):
    """onAddElementClick"""
    func = "onAddElementClick"

    # ask user to select the type of element and its hash algorithm
    if(self.pdef.Rules == DEFINES.PsRules):
      addElementChoices = self.addElementChoicesPs
    elif(self.pdef.Rules == DEFINES.PoRules):
      addElementChoices = self.addElementChoicesPo
    else:
      print("%s - invalid pdef.Rules=%d" % (func, self.pdef.Rules))
      return

    message = "Select the type of element and its hash algorithm"
    title   = "Add Element Selections"
    dialog = wx.SingleChoiceDialog(None, message, title, addElementChoices)
    if dialog.ShowModal() == wx.ID_OK:
      requestedElement = dialog.GetStringSelection()
    else:
      dialog.Destroy()
      return          # cancel out

    dialog.Destroy()
    self.StatusBar.SetStatusText("Adding a %s element to this LIST" % (requestedElement))

    print("%s: adding %s" % (func, requestedElement))  # DBGDBG
    self.deleteElementButton.Enable( True )
    currentListObject = self.pdef.getCurrentListObject()
    self.selectElementEdit.Enable( True )
    currentElementsCnt = int(self.numberElementsEdit.GetValue())
    currentElementsCnt += 1
    self.numberElementsEdit.ChangeValue(str(currentElementsCnt))

    # if an element is being shown, hide it.  Then show the new one
    if(currentListObject.CurrentElementView != DEFINES.ELEMENT_NAME_NONE):
      self.hideThisPanel(currentListObject.CurrentElementView)

    currentListObject.CurrentElementView = requestedElement
    self.selectElementEdit.Append(requestedElement)
    currentSelection = self.selectElementEdit.GetSelection()
    #print("%s: currentSelection=%d newSelection=%d" % (func, currentSelection, currentSelection+1)) # DBGDBG
    self.selectElementEdit.SetSelection(currentSelection + 1)
    self.selectElementEdit.SetValue(requestedElement)
    self.updateAddElementChoicesAfterAdd(requestedElement)
    self.visibleElement = requestedElement

    # Create a new element of selected spec and populate into currentListObject.MleDefData
    elementType, hashAlg = requestedElement.split('-')

    if hashAlg == 'LEGACY':
      if elementType == 'SBIOS':
        element = SBIOSLegacy()
        defdata = SBIOSLEGACY_DEF()
      elif elementType == 'MLE':
        element = MLELegacy()
        defdata = MLELEGACY_DEF()
      elif elementType == 'PCONF':
        element = PCONFLegacy()
        defdata = PCONFLEGACY_DEF()
      else:
        print ("ERROR: invalid element")
    else:
      if elementType == 'SBIOS':
        element = SBIOS(DEFINES.TPM_ALG_HASH[hashAlg])      # GUI panel
        defdata = SBIOS_DEF(DEFINES.TPM_ALG_HASH[hashAlg])  # Element defined in pdef.py
      elif elementType == 'STM':
        element = STM(DEFINES.TPM_ALG_HASH[hashAlg])
        defdata = STM_DEF(DEFINES.TPM_ALG_HASH[hashAlg])
      elif elementType == 'MLE':
        element = MLE(DEFINES.TPM_ALG_HASH[hashAlg])
        defdata = MLE_DEF(DEFINES.TPM_ALG_HASH[hashAlg])
      elif elementType == 'PCONF':
        element = PCONF(DEFINES.TPM_ALG_HASH[hashAlg])
        defdata = PCONF_DEF(DEFINES.TPM_ALG_HASH[hashAlg])
      else:
        print ("ERROR: invalid element")

    currentListObject.ElementDefData.append(defdata)
    element.createOrShowPanel(wx, self, self.parent, self.pdef, self.StatusBar)
    self.includedElements.append(element)

    # Note - panels were constructed with the correct hashAlg, so no need to pass that thru here
    # Note - iterators not used here since need to update the pdef's  xxxDefData.IncludeXXX not the array's

    self.selectElementEdit.Enable(True)
    self.parent.Layout()


  def syncVersion(self, rule):
    currentList = self.pdef.getCurrentListObject()
    listversion = str(currentList.ListVersionMajor)+'.'+str(currentList.ListVersionMinor)
    self.versionEdit.ChangeValue(listversion)
    if rule == DEFINES.PoRules:
      enable = True
    else:
      enable = False
    for element in self.includedElements:
      element.restorePanel(currentList, self.pdef.MaxHashes)
      element.enableDisableOverridePsPolicy(enable)


  def checkListModified(self, pdef):
    """checkListModified - return True if any list has been modified, else False"""

    # pdef.PolListInfo is a dictionary of 8 PLIST_DEF's from '0' to '7'
    # or None if that list was not added
    # i.e. {'0':PLIST_DEF or None, ... '7':PLIST_DEF or None}
    #
    i = '0'
    while(i<'8'):
      #print("checkListModified list %s" % (i))  # DBGDBG
      if(pdef.PolListInfo[i] != None):              # if list exists
        if(pdef.PolListInfo[i].ListModified == True):
          print("checkListModified Return - list %s was modified" % (i))  # DBGDBG
          return True

      i = str(int(i) + 1)

    return False


  def setListModified(self):
    """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""

    currentList = self.pdef.getCurrentListObject()
    #also set pdef.Modified for saving file\
    self.pdef.Modified =  True
    #print("setListModified - ListModified=%s" % (currentList.ListModified))  # DBGDBG
    if(currentList.ListModified == False):
      currentList.RevocationCounter += 1
      self.resetButton.Enable(True)

      self.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
      currentList.ListModified = True

  def rebuildSelectElementChoices(self):
    """rebuildSelectElementChoices - rebuild selectElementEdit's choices list for the elements existing in this view"""
    func = 'rebuildSelectElementChoices'

    self.selectElementEdit.Clear()
    self.selectElementEdit.Append('None')
    # For each existing element in this list (ie IncludeXXXX==True)
    currentList = self.pdef.getCurrentListObject()
    for element in currentList.ElementDefData:
      self.selectElementEdit.Append(element.Name)


  # remove the added element from the add element selection list
  def updateAddElementChoicesAfterAdd(self, requestedElement):
    """updateAddElementChoicesAfterAdd"""
    func = 'updateAddElementChoicesAfterAdd'

    if(self.pdef.Rules == DEFINES.PoRules):
      self.addElementChoicesPo.remove(requestedElement)
      if(len(self.addElementChoicesPo) == 0):
        self.addElementButton.Enable(False)
    if(self.pdef.Rules == DEFINES.PsRules):
      self.addElementChoicesPs.remove(requestedElement)
      if(len(self.addElementChoicesPs) == 0):
        self.addElementButton.Enable(False)

  # append the deleted element to the add element selection list
  def updateAddElementChoicesAfterDelete(self, deletedElement):
    """updateAddElementChoicesAfterDelete"""
    func='updateAddElementChoicesAfterDelete'

    # append the deleted element to the add element selection list
    self.addElementChoicesPs.append(deletedElement)
    self.addElementChoicesPo.append(deletedElement)


  # rebuild the add element selection list to include all the elements that don't exist
  def rebuildAddElementChoices(self):
    """rebuildAddElementChoices"""
    self.rebuildAddElementChoicesForPoRules()
    self.rebuildAddElementChoicesForPsRules()

  # if a PO rules element doesn't exist, add it to the selections list
  def rebuildAddElementChoicesForPoRules(self):
    """rebuildAddElementChoicesForPoRules"""
    func='rebuildAddElementChoicesForPoRules'

    #Element = DEFINES.ELEMENT_PO_RULES
    self.addElementChoicesPo = []
    self.addElementChoicesPo += DEFINES.ELEMENT_PO_RULES
    currentList = self.pdef.getCurrentListObject()

    for element in currentList.ElementDefData:
      if element.Name in self.addElementChoicesPo:
        self.addElementChoicesPo.remove(element.Name)
      else:
        print ("Element Name %s not found in Elements for PO rule" %(element.Name))

    if len(currentList.ElementDefData) >= 8 or len(self.addElementChoicesPs) == 0:
      flag = False
    else:
      flag = True
    self.addElementButton.Enable(flag)
    #print("%s - addElementChoicesPo=%s" % (func, self.addElementChoicesPo)) #DBGDBG

  # if a PS rules element doesn't exist, add it to the selections list
  def rebuildAddElementChoicesForPsRules(self):
    """rebuildAddElementChoicesForPsRules"""
    func='rebuildAddElementChoicesForPsRules'

    #Element = DEFINES.ELEMENT                    # gets all the elements i.e. = PS rules
    self.addElementChoicesPs = []
    self.addElementChoicesPs += DEFINES.ELEMENT   # gets all the elements i.e. = PS rules
    currentList = self.pdef.getCurrentListObject()

    for element in currentList.ElementDefData:
      if element.Name in self.addElementChoicesPs:
        self.addElementChoicesPs.remove(element.Name)
      else:
        print ("Element Name %s not found in Elements for PS rule" %(element.Name))

    if len(currentList.ElementDefData) >= 8 or len(self.addElementChoicesPs) == 0:
      flag = False
    else:
      flag = True
    self.addElementButton.Enable(flag)
    #print("%s - addElementChoicesPs=%s" % (func, self.addElementChoicesPs)) #DBGDBG

  def loadAndDisplayPlistDefFile(self, file, wx, pdef, statusBar, parent):
    """ loadAndDisplayPlistDefFile - get a saved plistDef object from a PDEF file and update the list panel"""
    func = 'loadAndDisplayPlistDefFile'

    self.pdef = pdef
    self.StatusBar = statusBar
    self.parent = parent

    print("%s load plistDef %d, NumLists=%d" % (func, pdef.CurrentListView, pdef.NumLists))     # DBGDBG
    currentListObject = self.pdef.getCurrentListObject()


    # If this list is to be the displayed list panel[ie pdef.CurrentListView]
    # then restore the list panel & enable/disable the AddElement buttons
    # restore the list's element panels that exist but hide them
    # only show & restore the specified element [ie list.CurrentElementView]
    #
    print("%s thisListNum=%d, CurrentListView=%d" % (func, pdef.CurrentListView, pdef.CurrentListView))     # DBGDBG
    if(self.listPanelWidgets == []):
      self.createListPanel(wx, parent, pdef.CurrentListView, pdef, statusBar)
    else:
      # in case list or element panels all ready exist ...
      self.hideListPanel()
      for i in self.listPanelWidgets:
        i.Show()

    self.setListPanelToCurrentListView()
    #currentListObject.ListModified = False

  def printPlistDefs(self, pdef, f):
    """printPlistDefs - write all created PLIST_DEFs to the specified human readable text file for printing"""

    # pdef.PolListInfo is a dictionary of 8 PLIST_DEF's from '0' to '7'
    # or None if that list was not added
    # i.e. {'0':PLIST_DEF or None, ... '7':PLIST_DEF or None}
    #
    i = '0'             # i is 0 based index for loop control
    cnt = '1'         # cnt is 1 based 'i' for printing
    while(i<'8'):
      print("PlistInfo", cnt, " = ", pdef.PolListInfo[i], file=f)
      if(pdef.PolListInfo[i] != None):
        self.printPlistDef(pdef.PolListInfo[i], f)     # write this PolListInfo[]

      i = str(int(i) + 1)
      cnt = str(int(cnt) + 1)

  def printPlistDef(self, plistDef, f):
    """printPlistDef - write this PLIST_DEF to the specified human readable text file for printing"""

    #print("printPlistDef - PLIST_DEF object: %s" % (plistDef))     # DBGDBG

    print("LdefSize",             " = ", plistDef.LdefSize,            file=f)
    print("Tag",                  " = ", plistDef.Tag,                 file=f)
    print("ListVersion",          " = ", plistDef.ListVersionMajor, ".", plistDef.ListVersionMinor, sep='', file=f)
    print("ListValid",            " = ", plistDef.ListValid,           file=f)
    print("ListModified",         " = ", plistDef.ListModified,        file=f)
    print("SigAlgorithm",         " = ", hex(plistDef.SigAlgorithm),        file=f)
    print("sigAlgorithmHash",     " = ", hex(plistDef.sigAlgorithmHash),    file=f)
    print("PolicyElementSize",    " = ", plistDef.PolicyElementSize,   file=f)
    print("CurrentElementView",   " = ", plistDef.CurrentElementView,  file=f)
    print("SyncRevCount",         " = ", plistDef.SyncRevCount,        file=f)
    print("AllowedCounter",       " = ", plistDef.RevokeCounter,       file=f)
    print("RevocationCounter",    " = ", plistDef.RevocationCounter,   file=f)
    print("KeySize",              " = ", plistDef.KeySize,             file=f)
    print("PubKeyFile",           " = ", plistDef.PubKeyFile,          file=f)
    print("PvtKeyFile",           " = ", plistDef.PvtKeyFile,          file=f)

    currentListObject = plistDef

    # print the element summary showing which elements were created
    # Lists always contain all elements, even if they haven't been added
    # so need to check if they should be included
    for element in plistDef.ElementDefData:
      print("%s DefData[Index]"% (element.Name),  " = ", element,  file=f)
      element.printDef(f)
      print("\n", file=f)         # for readability


#  def enablePconfOverridePsPolicyCheckbox(self, value):
#    """enablePconfOverridePsPolicyCheckbox - if current list has a PCONF element, enable its OverridePsPolicy checkbox"""
#
#    currentList = self.pdef.getCurrentListObject()
#    if(currentList.PconfDefData[DEFINES.DEFDATA_INDEX['SHA256']].IncludeInList == True):
#      pconf256.enablePconfOverridePsPolicyCheckbox(value)
#    if(currentList.PconfDefData[DEFINES.DEFDATA_INDEX['SHA1']].IncludeInList == True):
#      pconf1.enablePconfOverridePsPolicyCheckbox(value)
#    if(currentList.PconfLegacyDefData[DEFINES.DEFDATA_INDEX['SHA1']].IncludeInList == True):
#      pconf0.enablePconfOverridePsPolicyCheckbox(value)


  def hideAllPanels( self ):
    """hideAllPanels - hide all the element panels"""

    for element in self.includedElements:
      element.hidePanel()


  def hideThisPanel( self, panelToHide ):
    """hideThisPanel"""

    for element in self.includedElements:
      found = element.isElementType(panelToHide)
      if found:
        element.hidePanel()

    print("hideThisPanel: %s" % (panelToHide)) # DBGDBG

  # the last function in the file doesn't show up in the scope list in Understand for some reason!
  def stub(self):
    pass

