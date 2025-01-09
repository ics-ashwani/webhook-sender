package com.webhook.framework.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/webhook")
public class WebhookController
{
    @PostMapping
    public ResponseEntity<String> handleWebhook(@RequestBody Map<String, Object> payload, @RequestHeader("X-Signature") String signature) throws JsonProcessingException {
        // Step 1: Validate the webhook signature
        if (!validateSignature(payload, signature)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid signature");
        }

        // Step 2: Process the payload
        System.out.println("Received payload: " + payload);

        // Step 3: Acknowledge the webhook
        return ResponseEntity.ok("Webhook received successfully");
    }

    private boolean validateSignature(Map<String, Object> payload, String signature) throws JsonProcessingException {
        String secretKey = "tc639NswwXGBVpxz4WKCh81upoDooaBoV1ulrEWBV5drsItOvHhx55w6CAE5yVhZ1rD90YTv0cnLF4BFgOEbnLLqiQFHmRLJDx2fza72hG115ISa2ZGPTiawf6wMbVdseL";
        String payloadString = new ObjectMapper().writeValueAsString(payload);
        String computedHash = hmacSha256(secretKey, payloadString);

        return computedHash.equals(signature);
    }

    private String hmacSha256(String key, String data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while generating HMAC", e);
        }
    }
}
