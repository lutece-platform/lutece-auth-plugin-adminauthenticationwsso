/*
* Copyright (c) 2002-2013, Mairie de Paris
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
package fr.paris.lutece.plugins.adminauthenticationwsso;

import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.authentication.AdminAuthentication;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.ldap.LdapUtil;

import java.text.MessageFormat;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import javax.security.auth.login.LoginException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;


/**
 * Data authentication module for admin authentication
 */
public class AdminWssoAuthentication implements AdminAuthentication
{
    //Constant
    private static final String CONSTANT_WILDCARD = "*";

    // wsso
    private static final String PROPERTY_AUTH_SERVICE_NAME = "adminauthenticationwsso.service.name";
    private static final String PROPERTY_COOKIE_AUTHENTIFICATION = "adminauthenticationwsso.cookie.authenticationMode"; // mode d?authentification, login/pwd ou certificat
    private static final String PROPERTY_COOKIE_WSSOGUID = "adminauthenticationwsso.cookie.wssoguid"; // L?identifiant h?xa unique de l?utilisateur
    private static final String PROPERTY_COOKIE_LASTNAME = "adminauthenticationwsso.cookie.lastname"; // Nom de l'utilisateur
    private static final String PROPERTY_COOKIE_FIRSTNAME = "adminauthenticationwsso.cookie.firstname"; // Pr?nom de l'utilisateur
    private static final String PROPERTY_COOKIE_EMAIL = "adminauthenticationwsso.cookie.email"; // Email de l'utilisateur
    
    public static final String WSSO_CHANGE_PASSWORD_URL = "adminauthenticationwsso.url.changePassword"; //url de changement de password

    //ldap
    private static final String PROPERTY_INITIAL_CONTEXT_PROVIDER = "adminauthenticationwsso.ldap.initialContextProvider";
    private static final String PROPERTY_PROVIDER_URL = "adminauthenticationwsso.ldap.connectionUrl";
    private static final String PROPERTY_BIND_DN = "adminauthenticationwsso.ldap.connectionName";
    private static final String PROPERTY_BIND_PASSWORD = "adminauthenticationwsso.ldap.connectionPassword";
    private static final String PROPERTY_USER_DN_SEARCH_BASE = "adminauthenticationwsso.ldap.userBase";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID = "adminauthenticationwsso.ldap.userSearch.guid";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA = "adminauthenticationwsso.ldap.userSearch.criteria";
    private static final String PROPERTY_USER_SUBTREE = "adminauthenticationwsso.ldap.userSubtree";
    private static final String PROPERTY_DN_ATTRIBUTE_GUID = "adminauthenticationwsso.ldap.dn.attributeName.wssoGuid";
    private static final String PROPERTY_DN_ATTRIBUTE_FAMILY_NAME = "adminauthenticationwsso.ldap.dn.attributeName.familyName";
    private static final String PROPERTY_DN_ATTRIBUTE_GIVEN_NAME = "adminauthenticationwsso.ldap.dn.attributeName.givenName";
    private static final String PROPERTY_DN_ATTRIBUTE_EMAIL = "adminauthenticationwsso.ldap.dn.attributeName.email";
    private static final String ATTRIBUTE_GUID = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GUID );
    private static final String ATTRIBUTE_FAMILY_NAME = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_FAMILY_NAME );
    private static final String ATTRIBUTE_GIVEN_NAME = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GIVEN_NAME );
    private static final String ATTRIBUTE_EMAIL = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_EMAIL );
    
    /* comparator for sorting - date ascendant order */
    private static final Comparator<AdminWssoUser> COMPARATOR_USER = new Comparator<AdminWssoUser>(  )
        {
            public int compare( AdminWssoUser user1, AdminWssoUser user2 )
            {
                int nOrder = user1.getLastName(  ).toUpperCase(  ).compareTo( user2.getLastName(  ).toUpperCase(  ) );

                if ( nOrder == 0 )
                {
                    nOrder = user1.getFirstName(  ).toUpperCase(  ).compareTo( user2.getFirstName(  ).toUpperCase(  ) );

                    if ( nOrder == 0 )
                    {
                        nOrder = user1.getEmail(  ).toUpperCase(  ).compareTo( user2.getEmail(  ).toUpperCase(  ) );
                    }
                }

                return nOrder;
            }
        };

    /**
     * Search controls for the user entry search
     */
    private SearchControls _scUserSearchControls;

    /**
     *
     */
    public AdminWssoAuthentication(  )
    {
        super(  );
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getAuthServiceName()
     */
    public String getAuthServiceName(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_AUTH_SERVICE_NAME );
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getAuthType(javax.servlet.http.HttpServletRequest)
     */
    public String getAuthType( HttpServletRequest request )
    {
        Cookie[] cookies = request.getCookies(  );
        String strAuthType = request.getAuthType(  );

        for ( int i = 0; i < cookies.length; i++ )
        {
            Cookie cookie = cookies[i];

            if ( cookie.getName(  ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_AUTHENTIFICATION ) ) )
            {
                strAuthType = cookie.getValue(  );
            }
        }

        return strAuthType;
    }

    /**
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#login(java.lang.String, java.lang.String, javax.servlet.http.HttpServletRequest)
     */
    public AdminUser login( String strAccessCode, String strUserPassword, HttpServletRequest request )
        throws LoginException
    {
        // There is no login required : the user is supposed to be already authenticated
        return getHttpAuthenticatedUser( request );
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#logout(fr.paris.lutece.portal.business.user.authentication.AdminUser)
     */
    public void logout( AdminUser user )
    {
        // TODO Auto-generated method stub
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getAnonymousUser()
     */
    public AdminUser getAnonymousUser(  )
    {
        throw new java.lang.UnsupportedOperationException( 
            "La methode getAnonymousUser() n'est pas encore implementee." );
    }

    /**
     * Always return true;
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#isExternalAuthentication()
     */
    public boolean isExternalAuthentication(  )
    {
        return true;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getHttpAuthenticatedUser(javax.servlet.http.HttpServletRequest)
     */
    public AdminUser getHttpAuthenticatedUser( HttpServletRequest request )
    {
        Cookie[] cookies = request.getCookies(  );
        AdminWssoUser user = null;
        String strUserID = null;
        String strFamilyName = null;
        String strGivenName = null;
        String strEmail = "";

        for ( int i = 0; i < cookies.length; i++ )
        {
            Cookie cookie = cookies[i];

            if ( cookie.getName(  ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_WSSOGUID ) ) )
            {
                strUserID = cookie.getValue(  );
            }
            else if ( cookie.getName(  ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_LASTNAME ) ) )
            {
                strFamilyName = cookie.getValue(  );
            }
            else if ( cookie.getName(  ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_FIRSTNAME ) ) )
            {
                strGivenName = cookie.getValue(  );
            }
            else if ( cookie.getName(  ).equals( AppPropertiesService.getProperty( PROPERTY_COOKIE_EMAIL ) ) )
            {
                strEmail = cookie.getValue(  );
            }
        }

        if ( strUserID != null )
        {
            user = new AdminWssoUser( strUserID, this );
            user.setLastName( strFamilyName );
            user.setFirstName( strGivenName );
            user.setEmail( strEmail );
        }

        return user;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getLoginPageUrl()
     */
    public String getLoginPageUrl(  )
    {
        return null; // TODO
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getNewAccountPageUrl()
     */
    public String getChangePasswordPageUrl(  )
    {
        return WSSO_CHANGE_PASSWORD_URL;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getDoLoginUrl()
     */
    public String getDoLoginUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getDoLogoutUrl()
     */
    public String getDoLogoutUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getNewAccountPageUrl()
     */
    public String getNewAccountPageUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getViewAccountPageUrl()
     */
    public String getViewAccountPageUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getLostPasswordPageUrl()
     */
    public String getLostPasswordPageUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getLostPasswordPageUrl()
     */
    public String getLostLoginPageUrl(  )
    {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getUserList()
     */
    public Collection getUserList( String strParameterLastName, String strParameterFirstName, String strParameterEmail )
    {
        ArrayList<AdminWssoUser> userList = new ArrayList<AdminWssoUser>(  );
        SearchResult sr = null;
        Object[] messageFormatParam = new Object[3];

        DirContext context = null;

        messageFormatParam[0] = checkSyntax( strParameterLastName + CONSTANT_WILDCARD );
        messageFormatParam[1] = checkSyntax( strParameterFirstName + CONSTANT_WILDCARD );
        messageFormatParam[2] = checkSyntax( strParameterEmail + CONSTANT_WILDCARD );

        String strUserSearchFilter = MessageFormat.format( getUserDnSearchFilterByCriteria(  ), messageFormatParam );

        try
        {
            _scUserSearchControls = new SearchControls(  );
            _scUserSearchControls.setSearchScope( getUserDnSearchScope(  ) );
            _scUserSearchControls.setReturningObjFlag( true );
            _scUserSearchControls.setCountLimit( 0 );

            context = LdapUtil.getContext( getInitialContextProvider(  ), getProviderUrl(  ), getBindDn(  ),
                    getBindPassword(  ) );

            NamingEnumeration userResults = LdapUtil.searchUsers( context, strUserSearchFilter,
                    getUserDnSearchBase(  ), "", _scUserSearchControls );

            AppLogService.debug( this.getClass(  ).toString(  ) + " : Search users - LastName : " +
                messageFormatParam[0] + "- FirstName : " + messageFormatParam[1] + "- Email : " +
                messageFormatParam[2] );

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
                        "' with search filter : " + getDebugInfo( strUserSearchFilter ) + " - last name is null" );
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
                        "' with search filter : " + getDebugInfo( strUserSearchFilter ) + " - first name is null" );
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
                        "' with search filter : " + getDebugInfo( strUserSearchFilter ) + " - e-mail is null" );
                }

                //guid
                Attribute attributeGuId = attributes.get( ATTRIBUTE_GUID );
                String strWssoId = "";

                if ( attributeGuId != null )
                {
                    strWssoId = attributeGuId.get(  ).toString(  );

                    AdminWssoUser user = new AdminWssoUser( strWssoId, this );
                    user.setLastName( strLastName );
                    user.setFirstName( strFirstName );
                    user.setEmail( strEmail );
                    userList.add( user );
                    AppLogService.debug( this.getClass(  ).toString(  ) + " : Result - LastName : " +
                        user.getLastName(  ) + "- FirstName : " + user.getFirstName(  ) + "- Email : " +
                        user.getEmail(  ) );
                }
                else
                {
                    AppLogService.error( "Error while searching for users '" + attributes.toString(  ) +
                        "' with search filter : " + getDebugInfo( strUserSearchFilter ) + " - guid is null" );
                }
            }

            Collections.sort( userList, COMPARATOR_USER );

            return userList;
        }
        catch ( CommunicationException e )
        {
            AppLogService.error( "Error while searching for users '" + "' with search filter : " +
                getDebugInfo( strUserSearchFilter ), e );

            return null;
        }
        catch ( NamingException e )
        {
            AppLogService.error( "Error while searching for users", e );

            return null;
        }
        finally
        {
            try
            {
                LdapUtil.freeContext( context );
            }
            catch ( NamingException naming )
            {
                //todo
            }
        }
    }

    /* (non-Javadoc)
     * @see fr.paris.lutece.portal.business.user.authentication.AdminAuthentication#getUserPublicData(java.lang.String)
     */
    public AdminUser getUserPublicData( String strId )
    {
        AdminWssoUser user = null;
        SearchResult sr = null;
        Object[] messageFormatParam = new Object[1];

        DirContext context = null;

        messageFormatParam[0] = strId;

        String strUserSearchFilter = MessageFormat.format( getUserDnSearchFilterByGUID(  ), messageFormatParam );

        try
        {
            _scUserSearchControls = new SearchControls(  );
            _scUserSearchControls.setSearchScope( getUserDnSearchScope(  ) );
            _scUserSearchControls.setReturningObjFlag( true );
            _scUserSearchControls.setCountLimit( 0 );

            context = LdapUtil.getContext( getInitialContextProvider(  ), getProviderUrl(  ), getBindDn(  ),
                    getBindPassword(  ) );

            NamingEnumeration userResults = LdapUtil.searchUsers( context, strUserSearchFilter,
                    getUserDnSearchBase(  ), "", _scUserSearchControls );
            AppLogService.debug( this.getClass(  ).toString(  ) + " : create user - GUID : " + messageFormatParam[0] );

            int count = 0;

            while ( ( userResults != null ) && userResults.hasMore(  ) )
            {
                sr = (SearchResult) userResults.next(  );

                Attributes attributes = sr.getAttributes(  );
                String strWssoId = attributes.get( ATTRIBUTE_GUID ).get(  ).toString(  );
                String strLastName = attributes.get( ATTRIBUTE_FAMILY_NAME ).get(  ).toString(  );
                String strFirstName = attributes.get( ATTRIBUTE_GIVEN_NAME ).get(  ).toString(  );
                String strEmail = attributes.get( ATTRIBUTE_EMAIL ).get(  ).toString(  );

                user = new AdminWssoUser( strWssoId, this );
                user.setLastName( strLastName );
                user.setFirstName( strFirstName );
                user.setEmail( strEmail );
                count++;
                AppLogService.debug( this.getClass(  ).toString(  ) + " : Result - LastName : " + user.getLastName(  ) +
                    "- FirstName : " + user.getFirstName(  ) + "- Email : " + user.getEmail(  ) );
            }

            // More than one user found (failure)
            if ( count > 1 )
            {
                AppLogService.error( "More than one entry in the directory for id " + strId );

                return null;
            }

            return user;
        }
        catch ( CommunicationException e )
        {
            AppLogService.error( "Error while searching for users '" + "' with search filter : " +
                getDebugInfo( strUserSearchFilter ), e );

            return null;
        }
        catch ( NamingException e )
        {
            AppLogService.error( "Error while searching for users", e );

            return null;
        }
        finally
        {
            try
            {
                LdapUtil.freeContext( context );
            }
            catch ( NamingException naming )
            {
                //todo
            }
        }
    }

    private String checkSyntax( String in )
    {
        return ( ( ( in == null ) || ( in.equals( "" ) ) ) ? "*" : in );
    }

    private String getDebugInfo( String strUserSearchFilter )
    {
        StringBuffer sb = new StringBuffer(  );
        sb.append( "userBase : " );
        sb.append( getUserDnSearchBase(  ) );
        sb.append( "\nuserSearch : " );
        sb.append( strUserSearchFilter );

        return sb.toString(  );
    }

    private String getInitialContextProvider(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_INITIAL_CONTEXT_PROVIDER );
    }

    private String getProviderUrl(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_PROVIDER_URL );
    }

    private String getUserDnSearchBase(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_BASE );
    }

    private String getUserDnSearchFilterByGUID(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID );
    }

    private String getUserDnSearchFilterByCriteria(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_CRITERIA );
    }

    private int getUserDnSearchScope(  )
    {
        String strSearchScope = AppPropertiesService.getProperty( PROPERTY_USER_SUBTREE );

        if ( strSearchScope.equalsIgnoreCase( "true" ) )
        {
            return SearchControls.SUBTREE_SCOPE;
        }

        return SearchControls.ONELEVEL_SCOPE;
    }

    private String getBindDn(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_DN );
    }

    private String getBindPassword(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_PASSWORD );
    }
}
