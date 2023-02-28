package com.seeyouletter.domain_member.enums.converter;

import com.seeyouletter.domain_member.enums.GenderType;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Converter
public class GenderTypeConverter implements AttributeConverter<GenderType, String> {

    @Override
    public String convertToDatabaseColumn(GenderType genderType) {
        if (Objects.isNull(genderType)) {
            return null;
        }
        return genderType.getType();
    }

    @Override
    public GenderType convertToEntityAttribute(String gender) {
        if (gender == null) {
            return null;
        }
        return GenderType.find(gender);
    }
}
