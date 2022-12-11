package com.seeyouletter.domain_letter.collection;

import lombok.Getter;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Getter
@Document
public class Letter {

    @Id
    private ObjectId id;

    private String title;

    public Letter(String title) {
        this.title = title;
    }

}
