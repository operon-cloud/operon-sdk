package com.operoncloud.sdk.auth;

import java.time.Instant;
import java.util.List;

/**
 * Represents an issued access token and associated claims.
 */
public final class Token {
    private final String accessToken;
    private final String participantDid;
    private final String channelId;
    private final String customerId;
    private final String workspaceId;
    private final String email;
    private final String name;
    private final List<String> tenantIds;
    private final List<String> roles;
    private final String memberId;
    private final String sessionId;
    private final String orgId;
    private final Instant expiry;

    public Token(
        String accessToken,
        String participantDid,
        String channelId,
        String customerId,
        String workspaceId,
        String email,
        String name,
        List<String> tenantIds,
        List<String> roles,
        String memberId,
        String sessionId,
        String orgId,
        Instant expiry
    ) {
        this.accessToken = accessToken;
        this.participantDid = participantDid;
        this.channelId = channelId;
        this.customerId = customerId;
        this.workspaceId = workspaceId;
        this.email = email;
        this.name = name;
        this.tenantIds = tenantIds;
        this.roles = roles;
        this.memberId = memberId;
        this.sessionId = sessionId;
        this.orgId = orgId;
        this.expiry = expiry;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getParticipantDid() {
        return participantDid;
    }

    public String getChannelId() {
        return channelId;
    }

    public String getCustomerId() {
        return customerId;
    }

    public String getWorkspaceId() {
        return workspaceId;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public List<String> getTenantIds() {
        return tenantIds;
    }

    public List<String> getRoles() {
        return roles;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getOrgId() {
        return orgId;
    }

    public Instant getExpiry() {
        return expiry;
    }
}
