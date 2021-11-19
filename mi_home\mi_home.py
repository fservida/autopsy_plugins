import jarray
import inspect

from java.lang import System, Class, IllegalArgumentException
from java.util.logging import Level
from java.io import File
from java.sql import DriverManager, SQLException
from javax.swing import JCheckBox, BoxLayout

from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils

import os
from time import mktime
from xml.dom import minidom
import xml.etree.ElementTree as ET
import json
import re
import HTMLParser
from datetime import datetime, timedelta


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class MiHomeIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "MiHome Analysis"

    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module for analysis of MiHome related DBs and log files - by Francesco Servida - School of Criminal Justice, University of Lausanne, Switzerland"

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO: Update class name to one that you create below
    def getDefaultIngestJobSettings(self):
        return MiHomeIngestModuleSettings()

    # TODO: Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, MiHomeIngestModuleSettings):
            raise IllegalArgumentException(
                "Expected settings argument to be instance of MiHomeIngestModuleSettings")
        self.settings = settings
        return MiHomeIngestModuleSettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return MiHomeIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class MiHomeIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(MiHomeIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

        # Settings
        self.log(Level.INFO, str(self.local_settings))

        self.context = context

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.4/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        # blackboard = Case.getCurrentCase().getServices().getBlackboard() #we're not using indexing

        # Get case
        case = Case.getCurrentCase().getSleuthkitCase()

        # For our example, we will use FileManager to get all
        # files with the word "test"
        # in the name and then count and read them
        # FileManager API: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1casemodule_1_1services_1_1_file_manager.html
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        db_files = fileManager.findFiles(dataSource, "miio.db") # if self.local_settings.get_parse_db() else []
        if self.local_settings.get_parse_settings():
            # Yes, Alerm, they have a typo in the file
            home_room_manager = fileManager.findFiles(dataSource, "home_room_manager_sp_.xml")
            home_env_info = fileManager.findFiles(dataSource, "home_env_info.xml")
            device_logs = fileManager.findFiles(dataSource, "config.xml", "data")
        else:
            home_room_manager, home_env_info, device_logs = [], [], []

        num_files = len(db_files) + len(home_room_manager) + len(home_env_info) + len(device_logs)

        self.log(Level.INFO, "found " + str(num_files) + " files")
        progressBar.switchToDeterminate(num_files)
        file_count = 0

        # Settings
        if self.local_settings.get_parse_settings():
            # Settings File
            for file in home_room_manager + home_env_info + device_logs:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing file: " + file.getName())
                file_count += 1

                # Make an artifact on the blackboard.
                # Set the DB file as an "interesting file" : TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          MiHomeIngestModuleFactory.moduleName, "Mi Home")
                art.addAttribute(att)

                # Write to file (any way to contour this?)
                lcl_setting_path = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".xml")
                ContentUtils.writeToFile(file, File(lcl_setting_path))

                self.parse_xml(lcl_setting_path, file)

                # Clean Up
                os.remove(lcl_setting_path)

                progressBar.progress(file_count)

        # FINISHED!
        # Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              "MiHome Analysis", "Analyzed %d files" % file_count)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def parse_xml(self, filename, file):
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
            for child in root:
                attribute_name = child.attrib.get("name", "")
                if "Log_Normal" in attribute_name:
                    # Use normal log parser
                    for log in json.loads(child.text).get("value", []):
                        device = log.get("did")
                        log_ts = ts_uniform_to_seconds(log.get("time"))
                        ev_type = log.get("type")
                        for payload in json.loads(log.get("value", "[]")):
                            payload = json.loads(payload)
                            ev_ts = ts_uniform_to_seconds(payload[0])
                            for item in payload[1]:
                                if item:
                                    event = item
                                    self.add_event(file, event, ev_ts, log_ts, ev_type, device)

                if "ht_stat" in attribute_name:
                    # Use Temperature Parser
                    pattern = re.compile(r"(?P<device_id>.*)_ht_stat*.")
                    device = re.match(pattern, attribute_name).group("device_id")
                    data = json.loads(child.text)
                    log_ts = ts_uniform_to_seconds(data.get("time"))
                    for log in json.loads(data.get("value", "[]")):
                        ev_ts = ts_uniform_to_seconds(log.get("time"))
                        for event, value in log.items():
                            if event != "time":
                                print("Event Type: " + event)
                                print("Event Value: " + value)
                                self.add_event(file, value, ev_ts, log_ts, event, device)

                if "env_data" in attribute_name:
                    # Use Env Parser
                    env_data = json.loads(HTMLParser.HTMLParser().unescape(child.text))
                    for item in env_data.get("description_list"):
                        device = item.get("did")
                        for detail in item.get("details", []):
                            ev_type = detail.get("prop")
                            ev_ts = detail.get("timestamp")
                            event = detail.get("description")
                            self.add_event(file, event, ev_ts, ev_ts, ev_type, device)

                if "home_room_content" in attribute_name:
                    # Use Env Parser
                    home_data = json.loads(HTMLParser.HTMLParser().unescape(child.text))
                    for home in home_data.get("homelist", []):
                        home_name =  home.get("name")
                        home_id = home.get("id")
                        home_address = home.get("address")
                        home_latitude = str(home.get("latitude"))
                        home_longitude = str(home.get("longitude"))
                        self.add_home(file, home_name, home_id, home_address, home_latitude, home_longitude)
                        for room in home.get("roomlist", []):
                            room_name = room.get("name")
                            room_id = room.get("id")
                            for device in room.get("dids", []):
                                print("Device: " + device)
                                self.add_device(file, room_name, room_id, device)
        except Exception as e:
            self.log(Level.INFO, "Error while processing file: " + file.getName())
            self.log(Level.INFO, "Error MSG: " + str(e))

    def add_event(self, file, event, ev_date, log_date, ev_type, ev_device):
        
        # Get Blackboard
        sk_case = Case.getCurrentCase().getSleuthkitCase()
        blackboard = sk_case.getBlackboard()
        
        # Artifact 
        art_type_id = blackboard.getOrAddArtifactType("ESC_IOT_MIHOME_EVENTS", "Mi Home - Events").getTypeID()
        artifact = file.newArtifact(art_type_id)
        
        # Attributes
        attributes = []

        att_event_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_EVENTS_EVENT_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event")
        att_log_ts_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_EVENTS_LOG_DATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Log Timestamp")
        att_ev_ts_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_EVENTS_EVENT_DATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Event Timestamp")
        att_ev_type_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_EVENTS_EVENT_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Type")
        att_ev_device_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_EVENTS_EVENT_DEVICE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device")

        attributes.append(BlackboardAttribute(att_event_id, MiHomeIngestModuleFactory.moduleName, event))
        attributes.append(BlackboardAttribute(att_log_ts_id, MiHomeIngestModuleFactory.moduleName, log_date))
        attributes.append(BlackboardAttribute(att_ev_ts_id, MiHomeIngestModuleFactory.moduleName, ev_date))
        attributes.append(BlackboardAttribute(att_ev_type_id, MiHomeIngestModuleFactory.moduleName, ev_type))
        attributes.append(BlackboardAttribute(att_ev_device_id, MiHomeIngestModuleFactory.moduleName, ev_device))

        artifact.addAttributes(attributes)

        blackboard.postArtifact(artifact, MiHomeIngestModuleFactory.moduleName)
    
    def add_home(self, file, home_name, home_id, home_address, home_latitude, home_longitude):
        
        # Get Blackboard
        sk_case = Case.getCurrentCase().getSleuthkitCase()
        blackboard = sk_case.getBlackboard()
        
        # Artifact 
        art_type_id = blackboard.getOrAddArtifactType("ESC_IOT_MIHOME_HOME", "Mi Home - Home Details").getTypeID()
        artifact = file.newArtifact(art_type_id)
        
        # Attributes
        attributes = []

        att_home_name_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_HOME_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name")
        att_home_id_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_HOME_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ID")
        att_home_address_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_HOME_ADDRESS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address")
        att_home_lat_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_HOME_LATITUDE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Latitude")
        att_home_lon_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_HOME_LONGITUDE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Longitude")

        attributes.append(BlackboardAttribute(att_home_name_id, MiHomeIngestModuleFactory.moduleName, home_name))
        attributes.append(BlackboardAttribute(att_home_id_id, MiHomeIngestModuleFactory.moduleName, home_id))
        attributes.append(BlackboardAttribute(att_home_address_id, MiHomeIngestModuleFactory.moduleName, home_address))
        attributes.append(BlackboardAttribute(att_home_lat_id, MiHomeIngestModuleFactory.moduleName, home_latitude))
        attributes.append(BlackboardAttribute(att_home_lon_id, MiHomeIngestModuleFactory.moduleName, home_longitude))

        artifact.addAttributes(attributes)

        blackboard.postArtifact(artifact, MiHomeIngestModuleFactory.moduleName)

    def add_device(self, file, room_name, room_id, device):
        
        # Get Blackboard
        sk_case = Case.getCurrentCase().getSleuthkitCase()
        blackboard = sk_case.getBlackboard()
        
        # Artifact 
        art_type_id = blackboard.getOrAddArtifactType("ESC_IOT_MIHOME_DEVICES", "Mi Home -  Rooms & Devices").getTypeID()
        artifact = file.newArtifact(art_type_id)
        
        # Attributes
        attributes = []

        att_room_name_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_DEVICES_ROOM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Room Name")
        att_room_id_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_DEVICES_ROOM_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Room ID")
        att_device_id_id = blackboard.getOrAddAttributeType("ESC_IOT_MIHOME_DEVICES_DEVICE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device ID")

        attributes.append(BlackboardAttribute(att_room_name_id, MiHomeIngestModuleFactory.moduleName, room_name))
        attributes.append(BlackboardAttribute(att_room_id_id, MiHomeIngestModuleFactory.moduleName, room_id))
        attributes.append(BlackboardAttribute(att_device_id_id, MiHomeIngestModuleFactory.moduleName, device))

        artifact.addAttributes(attributes)

        blackboard.postArtifact(artifact, MiHomeIngestModuleFactory.moduleName)

# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class MiHomeIngestModuleSettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.parse_log = True
        self.parse_settings = True

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def get_parse_log(self):
        return self.parse_log

    def set_parse_log(self, flag):
        self.parse_log = flag

    def get_parse_settings(self):
        return self.parse_settings

    def set_parse_settings(self, flag):
        self.parse_settings = flag

    def __str__(self):
        return "MiHome Parser - Settings: Parse_DB = {}, Parse_Settings = {}".format(
            self.parse_log, self.parse_settings)


# UI that is shown to user for each ingest job so they can configure the job.
class MiHomeIngestModuleSettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def log_checkbox_event(self, event):
        if self.log_parse_checkbox.isSelected():
            self.local_settings.set_parse_log(True)
        else:
            self.local_settings.set_parse_log(False)

    def settings_checkbox_event(self, event):
        if self.settings_parse_checkbox.isSelected():
            self.local_settings.set_parse_settings(True)
        else:
            self.local_settings.set_parse_settings(False)

    def initComponents(self):
        # self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.log_parse_checkbox = JCheckBox("Parse Device Logs", actionPerformed=self.log_checkbox_event)
        # self.add(self.log_parse_checkbox)
        # self.settings_parse_checkbox = JCheckBox("Parse Setting Files", actionPerformed=self.settings_checkbox_event)
        # self.add(self.settings_parse_checkbox)
        pass

    def customizeComponents(self):
        # self.log_parse_checkbox.setSelected(self.local_settings.get_parse_log())
        # self.settings_parse_checkbox.setSelected(self.local_settings.get_parse_settings())
        pass

    # Return the settings used
    def getSettings(self):
        return self.local_settings


def ts_uniform_to_seconds(timestamp):
    boundary = datetime.now()+timedelta(1) # Boundary is today + 1 day
    try:
        if datetime.fromtimestamp(timestamp) > boundary:
            # Provided timestamp is in millis or nanos, reduce
            return(ts_uniform_to_seconds(timestamp/1000))
        else:
            return(timestamp)
    except ValueError:
        return(ts_uniform_to_seconds(timestamp/1000))
