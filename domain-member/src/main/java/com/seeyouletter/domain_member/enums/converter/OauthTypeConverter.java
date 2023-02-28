package com.seeyouletter.domain_member.enums.converter;

import com.seeyouletter.domain_member.enums.OauthType;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Converter
public class OauthTypeConverter implements AttributeConverter<OauthType, String> {

    @Override
    public String convertToDatabaseColumn(OauthType oauthType) {
        if (Objects.isNull(oauthType)) {
            return null;
        }
        return oauthType.getType();
    }

    @Override
    public OauthType convertToEntityAttribute(String provider) {
        if (provider == null) {
            return null;
        }
        return OauthType.find(provider);
    }
}
