<%@ page errorPage="../../ErrorPage.jsp" %>

<jsp:useBean id="adminAuthenticationWsso" scope="session" class="fr.paris.lutece.plugins.adminauthenticationwsso.web.WSSOAuthenticationJspBean" />

<% response.sendRedirect( adminAuthenticationWsso.doChangeWssoPassword( ) ); %>