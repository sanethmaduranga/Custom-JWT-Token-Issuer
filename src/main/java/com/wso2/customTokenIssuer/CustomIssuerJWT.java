package com.wso2.customTokenIssuer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.Application;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.dto.ApplicationDTO;
import org.wso2.carbon.apimgt.impl.dto.JwtTokenInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class CustomIssuerJWT extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(CustomIssuerJWT.class);

    public CustomIssuerJWT() throws IdentityOAuth2Exception {
        super();
        log.debug("Initiating CustomIssuerJWT");
    }

    /**
     * Build a signed jwt token from OauthToken request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception
     */
    protected String buildJWTToken(OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        JWTClaimsSet jwtClaimsSet =
                createJWTClaimSet(null, request,
                        request.getOauth2AccessTokenReqDTO().getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
        String userName = request.getAuthorizedUser().getUserName();
        JwtTokenInfoDTO jwtTokenInfoDTO;

        try {
            Application application =
                    APIUtil.getApplicationByClientId(request.getOauth2AccessTokenReqDTO().getClientId());
            ApiMgtDAO apiMgtDAO = ApiMgtDAO.getInstance();
            Application applicationAttr = apiMgtDAO.getApplicationById(application.getId());
            jwtTokenInfoDTO =
                    APIUtil.getJwtTokenInfoDTO(application, userName, MultitenantUtils.getTenantDomain(userName));
            ApplicationDTO applicationDTO = new ApplicationDTO();
            applicationDTO.setId(application.getId());
            applicationDTO.setName(application.getName());
            applicationDTO.setOwner(application.getOwner());
            applicationDTO.setTier(application.getTier());
            applicationDTO.setUuid(application.getUUID());

            jwtClaimsSetBuilder.audience("http://org.wso2.apimgt/gateway");
            jwtClaimsSetBuilder.claim("application", applicationDTO);
            jwtClaimsSetBuilder.claim("tierInfo", jwtTokenInfoDTO.getSubscriptionPolicyDTOList());
            jwtClaimsSetBuilder.claim("keytype", application.getKeyType());
            jwtClaimsSetBuilder.claim("subscribedAPIs", jwtTokenInfoDTO.getSubscribedApiDTOList());
            jwtClaimsSetBuilder.claim("consumerKey",jwtClaimsSet.getClaim("azp"));
            jwtClaimsSetBuilder.claim("ApplicationAttributes", applicationAttr.getApplicationAttributes());

        } catch (APIManagementException e) {
            throw new IdentityOAuth2Exception("Error while generating Custom JWT", e);
        }

        jwtClaimsSet = jwtClaimsSetBuilder.build();
        return signJWT(jwtClaimsSet, request, null);
    }
}