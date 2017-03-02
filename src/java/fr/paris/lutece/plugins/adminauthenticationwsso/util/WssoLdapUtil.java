/*
 * Copyright (c) 2002-2014, Mairie de Paris
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
package fr.paris.lutece.plugins.adminauthenticationwsso.util;

import fr.paris.lutece.plugins.adminauthenticationwsso.AdminWssoAuthentication;
import fr.paris.lutece.plugins.adminauthenticationwsso.AdminWssoUser;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.ldap.LdapUtil;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


public class WssoLdapUtil
{
    private static final String CONSTANT_WILDCARD = "*";
    
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA = "adminauthenticationwsso.ldap.userSearch.criteria";
    private static final String PROPERTY_INITIAL_CONTEXT_PROVIDER = "adminauthenticationwsso.ldap.initialContextProvider";
    private static final String PROPERTY_PROVIDER_URL = "adminauthenticationwsso.ldap.connectionUrl";
    private static final String PROPERTY_BIND_DN = "adminauthenticationwsso.ldap.connectionName";
    private static final String PROPERTY_BIND_PASSWORD = "adminauthenticationwsso.ldap.connectionPassword";
    private static final String PROPERTY_USER_DN_SEARCH_BASE = "adminauthenticationwsso.ldap.userBase";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID = "adminauthenticationwsso.ldap.userSearch.guid";
    private static final String PROPERTY_USER_SUBTREE = "adminauthenticationwsso.ldap.userSubtree";
    private static final String PROPERTY_DN_ATTRIBUTE_GUID = "adminauthenticationwsso.ldap.dn.attributeName.wssoGuid";
    private static final String PROPERTY_DN_ATTRIBUTE_FAMILY_NAME = "adminauthenticationwsso.ldap.dn.attributeName.familyName";
    private static final String PROPERTY_DN_ATTRIBUTE_GIVEN_NAME = "adminauthenticationwsso.ldap.dn.attributeName.givenName";
    private static final String PROPERTY_DN_ATTRIBUTE_EMAIL = "adminauthenticationwsso.ldap.dn.attributeName.email";
    private static final String ATTRIBUTE_GUID = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GUID );
    private static final String ATTRIBUTE_FAMILY_NAME = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_FAMILY_NAME );
    private static final String ATTRIBUTE_GIVEN_NAME = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GIVEN_NAME );
    private static final String ATTRIBUTE_EMAIL = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_EMAIL );
    
    public static DirContext getNewContext( )
    {
        try
        {
           return LdapUtil.getContext( getInitialContextProvider(  ), getProviderUrl(  ), getBindDn(  ),
                    getBindPassword(  ) ); 
        }
        catch( Exception e)
        {
            AppLogService.error( "Unable to open a new connection to LDAP to "+ getProviderUrl(  ) );
            return null;
        }
    }
    
    public static List<AdminWssoUser> getWssoUserListFromEmail( DirContext context, String strEmailSearch )
    {
        ArrayList<AdminWssoUser> userList = new ArrayList<AdminWssoUser>(  );
        SearchResult sr = null;

        Object[] messageFormatParam = new Object[3];

        messageFormatParam[0] = checkSyntax( "" + CONSTANT_WILDCARD );
        messageFormatParam[1] = checkSyntax( "" + CONSTANT_WILDCARD );
        messageFormatParam[2] = checkSyntax( strEmailSearch + CONSTANT_WILDCARD );
        
        String strUserSearchFilter = MessageFormat.format( getUserDnSearchFilterByCriteria(  ), messageFormatParam );

        try
        {
            SearchControls scUserSearchControls = new SearchControls(  );
            scUserSearchControls.setSearchScope( getUserDnSearchScope(  ) );
            scUserSearchControls.setReturningObjFlag( true );
            scUserSearchControls.setCountLimit( 0 );

            NamingEnumeration userResults = LdapUtil.searchUsers( context, strUserSearchFilter, getUserDnSearchBase(  ), "", scUserSearchControls );

            AppLogService.debug( AdminWssoUser.class.toString(  ) + " : Search users - Email : " + strUserSearchFilter );

            while ( ( userResults != null ) && userResults.hasMore(  ) )
            {
                sr = (SearchResult) userResults.next(  );

                Attributes attributes = sr.getAttributes(  );

                //Last Name
                Attribute attributeLastName = attributes.get( ATTRIBUTE_FAMILY_NAME );
                String strLastName = "";

                if ( attributeLastName != null )
                {
                    strLastName = attributes.get( ATTRIBUTE_FAMILY_NAME ).get(  ).toString(  );
                }
                else
                {
                    AppLogService.error( "Error while searching for users '" + attributes.toString(  ) +
                        "' with search filter : " +  strUserSearchFilter  + " - last name is null" );
                }

                //First Name
                Attribute attributeFirstName = attributes.get( ATTRIBUTE_GIVEN_NAME );
                String strFirstName = "";

                if ( attributeLastName != null )
                {
                    strFirstName = attributeFirstName.get(  ).toString(  );
                }
                else
                {
                    AppLogService.error( "Error while searching for users '" + attributes.toString(  ) +
                        "' with search filter : " + strUserSearchFilter + " - first name is null" );
                }

                //Email
                Attribute attributeEmail = attributes.get( ATTRIBUTE_EMAIL );
                String strEmail = "";

                if ( attributeLastName != null )
                {
                    strEmail = attributeEmail.get(  ).toString(  );
                }
                else
                {
                    AppLogService.error( "Error while searching for users '" + attributes.toString(  ) +
                        "' with search filter : " + strUserSearchFilter + " - e-mail is null" );
                }

                //guid
                Attribute attributeGuId = attributes.get( ATTRIBUTE_GUID );
                String strWssoId = "";

                if ( attributeGuId != null )
                {
                    strWssoId = attributeGuId.get(  ).toString(  );
                    
                    AdminWssoUser user = null;
                    user = new AdminWssoUser( strWssoId, new AdminWssoAuthentication( ) );
                    user.setLastName( strLastName );
                    user.setFirstName( strFirstName );
                    user.setEmail( strEmail );
                    userList.add( user );
                    AppLogService.debug( WssoLdapUtil.class.toString(  ) + " : Result " +
                            "- LastName : " +  user.getLastName(  ) + 
                            "- FirstName : " + user.getFirstName(  ) + 
                            "- Email : " + user.getEmail(  ) );
                }
                else
                {
                    AppLogService.error( "Error while searching for users '" + attributes.toString(  ) +
                        "' with search filter : " +  strUserSearchFilter + " - guid is null" );
                }
            }
            return userList;
        }
        catch ( CommunicationException e )
        {
            AppLogService.error( "Error while searching for users '" + "' with search filter : " + strUserSearchFilter , e );
            return userList;
        }
        catch ( NamingException e )
        {
            AppLogService.error( "Error while searching for users " );
            return userList;
        }
    }
    
    
    public static String checkSyntax( String in )
    {
        return ( ( ( in == null ) || ( in.equals( "" ) ) ) ? "*" : in );
    }
    
    public static String getUserDnSearchFilterByCriteria(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA );
    }
    
    public static String getInitialContextProvider(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_INITIAL_CONTEXT_PROVIDER );
    }

    public static String getProviderUrl(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_PROVIDER_URL );
    }

    public static String getUserDnSearchBase(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_BASE );
    }

    public static String getUserDnSearchFilterByGUID(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID );
    }

    public static int getUserDnSearchScope(  )
    {
        String strSearchScope = AppPropertiesService.getProperty( PROPERTY_USER_SUBTREE );

        if ( strSearchScope.equalsIgnoreCase( "true" ) )
        {
            return SearchControls.SUBTREE_SCOPE;
        }

        return SearchControls.ONELEVEL_SCOPE;
    }

    public static String getBindDn(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_DN );
    }

    public static String getBindPassword(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_PASSWORD );
    }
    
}
