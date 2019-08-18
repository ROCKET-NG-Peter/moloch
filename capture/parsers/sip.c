#include <string.h>
#include <ctype.h>
#include "moloch.h"


LOCAL  int SIPmessageField;
LOCAL  int SIPcallIDField;

LOCAL int sip_udp_parser(MolochSession_t *session, void *UNUSED(uw), const unsigned char *data, int len, int UNUSED(which))
{
        moloch_field_string_add(SIPmessageField, session, (char*)data, len, TRUE);


}

LOCAL void sip_udp_classify(MolochSession_t *session, const unsigned char *UNUSED(data), int len, int UNUSED(which), void *UNUSED(uw))
{

    moloch_session_add_protocol(session, "sip");
    moloch_parsers_register(session, sip_udp_parser, 0, 0);
}

void moloch_parser_init()
{

	SIPmessageField = moloch_field_define("sip", "lotermfield", "sip.message", "MESSAGE", "sip.message", "FULL SIP MESSAGE",
        	MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);
	SIPcallIDField = moloch_field_define("sip", "lotermfield", "sip.callid", "callID", "sip.callid", "Call ID",
		MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);
	SIPrequests = moloch_field_define("sip", "lotermfield", "sip.requests", "REQUESTS", "sip.requests", "REQUESTS",
		MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);
        SIPvia = moloch_field_define("sip", "lotermfield", "sip.via", "Via", "sip.via", "via",
	        MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);
        SIPfrom = moloch_field_define("sip", "lotermfield", "sip.from", "From", "sip.froma", "from",
	        MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);
        SIPto = moloch_field_define("sip", "lotermfield", "sip.to", "To", "sip.to", "to",
	        MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT, (char *)NULL);	

    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"SIP/2.0", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"REGISTER sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"INVITE sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"ACK sip:", 1, sip_udp_classify);	
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"BYE sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"CANCEL sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"UPDATE sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"REFER sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"PRACK sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"SUBSCRIBE sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"NOTIFY sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"PUBLISH sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"MESSAGE sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"INFO sip:", 1, sip_udp_classify);
    moloch_parsers_classifier_register_udp("sip", NULL, 0, (const unsigned char *)"OPTIONS sip:", 1, sip_udp_classify);

}
