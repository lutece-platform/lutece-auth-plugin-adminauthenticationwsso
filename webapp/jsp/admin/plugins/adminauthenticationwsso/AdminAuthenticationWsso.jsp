<%@ page errorPage="../../ErrorPage.jsp" %>

${ pageContext.response.sendRedirect( wSSOAuthenticationJspBean.doChangeWssoPassword( )) }
