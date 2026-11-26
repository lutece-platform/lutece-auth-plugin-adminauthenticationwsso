/*
 * Copyright (c) 2002-2026, City of Paris
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

import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.portal.service.csv.CSVMessageDescriptor;
import fr.paris.lutece.portal.service.csv.CSVMessageLevel;

/**
 * Checks of the lines of the WSSO CSV import (the core export layout: access code first, then 11 fixed columns)
 */
public class WssoAdminUserImportServiceTest extends LuteceTestCase
{
    private static final String EMAIL = "ay16-wsso-import@e2e.fr";
    private AdminUser _user;

    /**
     * Exposes the line check of the import
     */
    private static class TestableImportService extends WssoAdminUserImportService
    {
        List<CSVMessageDescriptor> check( String [ ] line )
        {
            return checkLineOfCSVFile( line, 1, Locale.FRENCH );
        }
    }

    @AfterEach
    public void removeUser( )
    {
        if ( _user != null )
        {
            AdminUserHome.remove( _user.getUserId( ) );
            _user = null;
        }
    }

    private static boolean hasError( List<CSVMessageDescriptor> messages )
    {
        return messages.stream( ).anyMatch( m -> m.getMessageLevel( ) == CSVMessageLevel.ERROR );
    }

    /**
     * AY-16: « update existing users » unchecked, the e-mail of the line (column 3) belongs to an existing admin: the line is refused
     */
    @Test
    public void testExistingEmailRefusedWhenUpdateUnchecked( )
    {
        _user = new AdminUser( );
        _user.setAccessCode( "ay16wsso" );
        _user.setLastName( "Upd" );
        _user.setFirstName( "E2e" );
        _user.setEmail( EMAIL );
        _user.setStatus( 0 );
        _user.setLocale( Locale.FRENCH );
        _user.setUserLevel( 3 );
        AdminUserHome.create( _user );

        TestableImportService service = new TestableImportService( );
        service.setUpdateExistingUsers( false );
        String [ ] line = {
                "otherguid", "Upd", "E2e", EMAIL, "0", "fr", "3", "false", "false", "", "", ""
        };

        org.junit.jupiter.api.Assertions.assertEquals( EMAIL, service.getEmail( line ) );
        org.junit.jupiter.api.Assertions.assertTrue( hasError( service.check( line ) ), "an existing e-mail must be refused when the update box is unchecked" );
    }
}
