package se.sensiblethings.addinlayer.extensions.security.serializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import se.sensiblethings.addinlayer.extensions.security.communication.MessagePayload;
import se.sensiblethings.disseminationlayer.communication.Message;

public class PayloadSerializer {
	public byte[] serializeMessage(MessagePayload payload) {
        ByteArrayOutputStream bos;
        ObjectOutputStream out;
        byte[] byteArray = null;
        try {
            bos = new ByteArrayOutputStream();
            out = new ObjectOutputStream(bos);
            out.writeUnshared(payload);
            byteArray = bos.toByteArray();
            out.reset();
            out.close();
            bos.reset();
            bos.close();

        } catch (Exception e) {
        	e.printStackTrace();
        }
        out = null;
        bos = null;
        return byteArray;
    }

    public MessagePayload deserializeMessage(byte[] stringRepresentation) {
        if (stringRepresentation == null) {
            return null;
        }
        ByteArrayInputStream bis;
        ObjectInputStream in = null;
        MessagePayload payload = null;
        try {

            bis = new ByteArrayInputStream(stringRepresentation);
            

            in = new ObjectInputStream(bis);
            payload = (MessagePayload) in.readUnshared();
            bis.reset();
            bis.close();
            //in.reset();
            in.close();
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return payload;
    }  
}
