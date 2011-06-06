/*
 * Copyright (c) 2002-2011, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.adminauthenticationwsso.service;

import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.xml.XmlUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;


/**
 *
 * @author lutecer
 */
public class WssoAdminUsersFileGeneratorService
{
    /////////////////////////////////////////////////////////////////////////////////
    // Constants
    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    /////////////////////////////////////////////////////////////////////////////////
    // Properties
    private static final String PROPERTY_APP_ID = "adminauthenticationwsso.appID";
    private static final String PROPERTY_APP_RESPONSABLE = "adminauthenticationwsso.appResponsable";
    private static final String PROPERTY_XML_STORAGE_FOLDER_PATH = "adminauthenticationwsso.path";
    private static final String PROPERTY_XML_FILE_NAME = "adminauthenticationwsso.fileName";
    private static final String PROPERTY_XMLFILEFORMAT_AUTORISATION_WSSO = "adminauthenticationwsso.wssofileformat.tag_autorisationWSSO";
    private static final String PROPERTY_XMLFILEFORMAT_APPLICATION_WSSO = "adminauthenticationwsso.wssofileformat.tag_applicationWSSO";
    private static final String PROPERTY_XMLFILEFORMAT_ATTR_APPLICATION_WSSO_APP_ID = "adminauthenticationwsso.wssofileformat.tag_appID";
    private static final String PROPERTY_XMLFILEFORMAT_TRANSMISSION_DATE = "adminauthenticationwsso.wssofileformat.tag_transmissionDate";
    private static final String PROPERTY_XMLFILEFORMAT_ATTR_TRANSMISSION_DATE_DATE = "adminauthenticationwsso.wssofileformat.tag_date";
    private static final String PROPERTY_XMLFILEFORMAT_APP_RESPONSABLE = "adminauthenticationwsso.wssofileformat.tag_appResponsable";
    private static final String PROPERTY_XMLFILEFORMAT_ATTR_APP_RESPONSABLE_MAIL = "adminauthenticationwsso.wssofileformat.tag_mail";
    private static final String PROPERTY_XMLFILEFORMAT_ALLOWED_USER = "adminauthenticationwsso.wssofileformat.tag_allowedUser";
    private static final String PROPERTY_XMLFILEFORMAT_ATTR_ALLOWED_USER_WSSO_GUID = "adminauthenticationwsso.wssofileformat.tag_wssoGUID";
    private static final String LOG_MESSAGE_OK = "\nWssoAdminUserFileGeneratorService : Update OK for file ";
    private static final String LOG_MESSAGE_NOK = "\nWssoAdminUserFileGeneratorService : Error when updating file ";

    /**
     *
     * Creates a new instance of WssoAdminUsersFileGeneratorService
     */
    public WssoAdminUsersFileGeneratorService(  )
    {
    }

    /**
     * Creates the XML string
     *
     * @param plugin the plugin
     * @return String the XML content of the admin user list
     */
    public static String getXml( Plugin plugin )
    {
        StringBuffer strXml = new StringBuffer(  );
        Date date = new Date(  );
        HashMap attrList = new HashMap(  );
        Collection<AdminUser> userList = AdminUserHome.findUserList(  );
        //AdminAuthentication auth = new AdminWssoAuthentication(  );
        //Collection<AdminWssoUser> userList = auth.getUserList( "", "", "" );

        //Open AutorisationWsso
        XmlUtil.beginElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_AUTORISATION_WSSO ) );

        //Open ApplicationWsso
        attrList.put( AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_ATTR_APPLICATION_WSSO_APP_ID ),
            AppPropertiesService.getProperty( PROPERTY_APP_ID ) );
        XmlUtil.beginElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_APPLICATION_WSSO ),
            attrList );
        attrList.clear(  );

        //Add transmissionDate
        DateFormat dateFormat = new SimpleDateFormat( DATE_FORMAT );
        attrList.put( AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_ATTR_TRANSMISSION_DATE_DATE ),
            dateFormat.format( date ) );
        XmlUtil.addEmptyElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_TRANSMISSION_DATE ),
            attrList );
        attrList.clear(  );

        //Add responsable
        attrList.put( AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_ATTR_APP_RESPONSABLE_MAIL ),
            AppPropertiesService.getProperty( PROPERTY_APP_RESPONSABLE ) );
        XmlUtil.addEmptyElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_APP_RESPONSABLE ),
            attrList );
        attrList.clear(  );

        //Add list of allowedUser
        for ( AdminUser user : userList )
        {
            attrList.put( AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_ATTR_ALLOWED_USER_WSSO_GUID ),
                user.getAccessCode(  ) );
            XmlUtil.addEmptyElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_ALLOWED_USER ),
                attrList );
            attrList.clear(  );
        }

        //Close applicationWsso
        XmlUtil.endElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_APPLICATION_WSSO ) );

        //Close autorisationWsso
        XmlUtil.endElement( strXml, AppPropertiesService.getProperty( PROPERTY_XMLFILEFORMAT_AUTORISATION_WSSO ) );

        return strXml.toString(  );
    }

    /**
     * Create or update the XML file with the getXml content
     *
     * @param plugin the plugin
     */
    public static String createXmlFile( Plugin plugin )
    {
        FileWriter fileXmlWriter = null;

        //String buffer for building the response page
        StringBuffer sbLogs = new StringBuffer(  );
        String strFileName = AppPropertiesService.getProperty( PROPERTY_XML_FILE_NAME );
        String strFolderPath = AppPathService.getPath( PROPERTY_XML_STORAGE_FOLDER_PATH, "" );

        try
        {
            // Test if the pushXml directory exist and create it if it doesn't exist
            if ( !new File( strFolderPath ).exists(  ) )
            {
                File fileFolder = new File( strFolderPath );
                fileFolder.mkdir(  );
            }

            // Creates a temporary XML file
            File fileXml = new File( strFolderPath + strFileName );
            File fileXmlDirectory = new File( strFolderPath );
            File fileXmlTemp = File.createTempFile( "tmp", null, fileXmlDirectory );
            fileXmlWriter = new FileWriter( fileXmlTemp );
            fileXmlWriter.write( getXml( plugin ) );
            fileXmlWriter.flush(  );
            fileXmlWriter.close(  );

            // Deletes the file if the file exists and renames the temporary file into the file
            removeXmlFile(  );
            fileXmlTemp.renameTo( fileXml );
            sbLogs.append( LOG_MESSAGE_OK + strFileName );
        }
        catch ( IOException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            sbLogs.append( LOG_MESSAGE_NOK + strFileName );
        }
        catch ( NullPointerException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            sbLogs.append( LOG_MESSAGE_NOK + strFileName );
        }

        return sbLogs.toString(  );
    }

    /**
     * Delete the XML file on the file system
     *
     */
    public static void removeXmlFile(  )
    {
        String strFileXml = AppPathService.getPath( PROPERTY_XML_STORAGE_FOLDER_PATH, "" ) +
            AppPropertiesService.getProperty( PROPERTY_XML_FILE_NAME );
        File file = new File( strFileXml );

        // Deletes the file if the file exists
        if ( file.exists(  ) )
        {
            file.delete(  );
        }
    }
}
