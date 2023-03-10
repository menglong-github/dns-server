package dns.message;

import dns.cache.ZoneCache;
import dns.constant.Constants;
import dns.core.*;
import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @ClassName MessageQuery
 * @Description TODO
 * @Author 梦龙
 * @Date 2022/2/17 11:27
 * @Version 1.0
 **/
public class MessageQuery {
    public static DatabaseReader reader = null;
    static {
        try {
            InputStream inputStream = Constants.class.getResourceAsStream(Constants.GEO_FILE_PATH);
            reader = new DatabaseReader.Builder(inputStream).withCache(new CHMCache()).build();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getClientIpAddress(Message message, String remoteIpAddress) {
        OPTRecord optRecord = message.getOPT();
        String clientIpAddress;
        if (optRecord != null && (optRecord.getOptions(EDNSOption.Code.CLIENT_SUBNET).size() != 0)) {
            clientIpAddress = ((ClientSubnetOption)(optRecord.getOptions(EDNSOption.Code.CLIENT_SUBNET).get(0))).getAddress().getHostAddress();
        } else {
            clientIpAddress = remoteIpAddress;
        }
        return clientIpAddress;
    }

    private static String getGeoCode(String ipAddress) {
        try {
            CountryResponse countryResponse = reader.country(InetAddress.getByName(ipAddress));
            return countryResponse.getCountry().getIsoCode();
        } catch (IOException | GeoIp2Exception ignored) {}
        return null;
    }

    public static void query(Message message, String remoteIpAddress) {
        try {
            String queryName = message.getQuestion().getName().toString().toLowerCase();
            Map<String, Zone> zoneMap = ZoneCache.queryZone(queryName);
            int questionType = message.getQuestion().getType();
            if (zoneMap == null) {
                int queryNameLength = queryName.length();
                for (int index = 0; index < queryNameLength; index++) {
                    if (queryName.charAt(index) == '.') {
                        zoneMap = ZoneCache.queryZone(queryName.substring(index + 1, queryNameLength));
                        if (zoneMap != null) {
                            break;
                        }
                    }
                }
            }
            if (zoneMap != null) {
                Zone geoZone = zoneMap.get(getGeoCode(getClientIpAddress(message, remoteIpAddress)));
                Name questionName = message.getQuestion().getName();
                if (geoZone != null) {
                    boolean dnssec = geoZone.dnssec && (message.getOPT() != null) && (message.getOPT().getFlags() == Type.TA);
                    if (questionType == Type.DS) {
                        RRset dsRrset = geoZone.findExactMatch(questionName, questionType);
                        if (dsRrset != null) {
                            List<Record> dsRecordList = dsRrset.rrs();
                            int dsRecordListLength = dsRecordList.size();
                            for (int dsRecordIndex = 0; dsRecordIndex < dsRecordListLength; dsRecordIndex++) {
                                message.addRecord(dsRecordList.get(dsRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> dsRRSIGRecordList = dsRrset.sigs();
                                int dsRRSIGRecordListLength = dsRRSIGRecordList.size();
                                for (int dsRRSIGRecordIndex = 0; dsRRSIGRecordIndex < dsRRSIGRecordListLength; dsRRSIGRecordIndex++) {
                                    message.addRecord(dsRRSIGRecordList.get(dsRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                            message.getHeader().unsetFlag(Flags.RD);
                            message.getHeader().unsetFlag(Flags.AD);
                            message.getHeader().setFlag(Flags.QR);
                            message.getHeader().setFlag(Flags.AA);
                            message.getHeader().setFlag(Flags.RD);
                            return;
                        }
                    } else {
                        SetResponse queryResponse = geoZone.findRecords(questionName, questionType);
                        if (queryResponse.isDelegation()) {
                            RRset nsRRset = queryResponse.getNS();
                            List<Record> nsRecordList = nsRRset.rrs();
                            int nsRecordListLength = nsRecordList.size();
                            Record nsRecord;
                            for (int nsRecordIndex = 0; nsRecordIndex < nsRecordListLength; nsRecordIndex++) {
                                nsRecord = nsRecordList.get(nsRecordIndex);
                                message.addRecord(nsRecord, Section.AUTHORITY);
                                if (nsRecord.getAdditionalName().subdomain(geoZone.getOrigin())) {
                                    Zone wildcardZone = zoneMap.get("*");
                                    RRset aRRset = geoZone.findExactMatch(nsRecord.getAdditionalName(), Type.A);
                                    RRset aaaaRRset = geoZone.findExactMatch(nsRecord.getAdditionalName(), Type.AAAA);
                                    if (aRRset != null) {
                                        List<Record> aRecordList = aRRset.rrs();
                                        int aRecordListLength = aRecordList.size();
                                        for (int aRecordIndex = 0; aRecordIndex < aRecordListLength; aRecordIndex++) {
                                            message.addRecord(aRecordList.get(aRecordIndex), Section.ADDITIONAL);
                                        }
                                        if (dnssec) {
                                            List<RRSIGRecord> aRRSIGRecordList = aRRset.sigs();
                                            int aRRSIGRecordListLength = aRRSIGRecordList.size();
                                            for (int aRRSIGRecordIndex = 0; aRRSIGRecordIndex < aRRSIGRecordListLength; aRRSIGRecordIndex++) {
                                                message.addRecord(aRRSIGRecordList.get(aRRSIGRecordIndex), Section.ADDITIONAL);
                                            }
                                        }
                                    } else if (wildcardZone != null) {
                                        aRRset = wildcardZone.findExactMatch(nsRecord.getAdditionalName(), Type.A);
                                        if (aRRset != null) {
                                            List<Record> aRecordList = aRRset.rrs();
                                            int aRecordListLength = aRecordList.size();
                                            for (int aRecordIndex = 0; aRecordIndex < aRecordListLength; aRecordIndex++) {
                                                message.addRecord(aRecordList.get(aRecordIndex), Section.ADDITIONAL);
                                            }
                                            if (dnssec) {
                                                List<RRSIGRecord> aRRSIGRecordList = aRRset.sigs();
                                                int aRRSIGRecordListLength = aRRSIGRecordList.size();
                                                for (int aRRSIGRecordIndex = 0; aRRSIGRecordIndex < aRRSIGRecordListLength; aRRSIGRecordIndex++) {
                                                    message.addRecord(aRRSIGRecordList.get(aRRSIGRecordIndex), Section.ADDITIONAL);
                                                }
                                            }
                                        }
                                    }
                                    if (aaaaRRset != null) {
                                        List<Record> aaaaRecordList = aaaaRRset.rrs();
                                        int aaaaRecordListLength = aaaaRecordList.size();
                                        for (int aaaaRecordIndex = 0; aaaaRecordIndex < aaaaRecordListLength; aaaaRecordIndex++) {
                                            message.addRecord(aaaaRecordList.get(aaaaRecordIndex), Section.ADDITIONAL);
                                        }
                                        if (dnssec) {
                                            List<RRSIGRecord> aaaaRRSIGRecordList = aaaaRRset.sigs();
                                            int aaaaRRSIGRecordListLength = aaaaRRSIGRecordList.size();
                                            for (int aaaaRRSIGRecordIndex = 0; aaaaRRSIGRecordIndex < aaaaRRSIGRecordListLength; aaaaRRSIGRecordIndex++) {
                                                message.addRecord(aaaaRRSIGRecordList.get(aaaaRRSIGRecordIndex), Section.ADDITIONAL);
                                            }
                                        }
                                    } else if (wildcardZone != null) {
                                        aaaaRRset = wildcardZone.findExactMatch(nsRecord.getAdditionalName(), Type.AAAA);
                                        if (aaaaRRset != null) {
                                            List<Record> aaaaRecordList = aaaaRRset.rrs();
                                            int aaaaRecordListLength = aaaaRecordList.size();
                                            for (int aaaaRecordIndex = 0; aaaaRecordIndex < aaaaRecordListLength; aaaaRecordIndex++) {
                                                message.addRecord(aaaaRecordList.get(aaaaRecordIndex), Section.ADDITIONAL);
                                            }
                                            if (dnssec) {
                                                List<RRSIGRecord> aaaaRRSIGRecordList = aaaaRRset.sigs();
                                                int aaaaRRSIGRecordListLength = aaaaRRSIGRecordList.size();
                                                for (int aaaaRRSIGRecordIndex = 0; aaaaRRSIGRecordIndex < aaaaRRSIGRecordListLength; aaaaRRSIGRecordIndex++) {
                                                    message.addRecord(aaaaRRSIGRecordList.get(aaaaRRSIGRecordIndex), Section.ADDITIONAL);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if (dnssec) {
                                List<RRSIGRecord> nsRRSIGRecordList = nsRRset.sigs();
                                int nsRRSIGRecordListLength = nsRRSIGRecordList.size();
                                for (int nsRRSIGRecordIndex = 0; nsRRSIGRecordIndex < nsRRSIGRecordListLength; nsRRSIGRecordIndex++) {
                                    message.addRecord(nsRRSIGRecordList.get(nsRRSIGRecordIndex), Section.AUTHORITY);
                                }
                            }
                            message.getHeader().unsetFlag(Flags.RD);
                            message.getHeader().unsetFlag(Flags.AD);
                            message.getHeader().setFlag(Flags.QR);
                            message.getHeader().setFlag(Flags.AA);
                            message.getHeader().setFlag(Flags.RD);
                            return;
                        } else if (queryResponse.isCNAME()) {
                            RRset cnameRRset = queryResponse.getCNAME();
                            List<Record> cnameRecordList = cnameRRset.rrs();
                            int cnameRecordListLength = cnameRecordList.size();
                            for (int cnameRecordIndex = 0; cnameRecordIndex < cnameRecordListLength; cnameRecordIndex++) {
                                message.addRecord(cnameRecordList.get(cnameRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> cnameRRSIGRecordList = cnameRRset.sigs();
                                int cnameRRSIGRecordListLength = cnameRRSIGRecordList.size();
                                for (int cnameRRSIGRecordIndex = 0; cnameRRSIGRecordIndex < cnameRRSIGRecordListLength; cnameRRSIGRecordIndex++) {
                                    message.addRecord(cnameRRSIGRecordList.get(cnameRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                            message.getHeader().unsetFlag(Flags.RD);
                            message.getHeader().unsetFlag(Flags.AD);
                            message.getHeader().setFlag(Flags.QR);
                            message.getHeader().setFlag(Flags.AA);
                            message.getHeader().setFlag(Flags.RD);
                            return;
                        } else if (queryResponse.isDNAME()) {
                            RRset dnameRRset = queryResponse.getDNAME();
                            List<Record> dnameRecordList = dnameRRset.rrs();
                            int dnameRecordListLength = dnameRecordList.size();
                            for (int dnameRecordIndex = 0; dnameRecordIndex < dnameRecordListLength; dnameRecordIndex++) {
                                message.addRecord(dnameRecordList.get(dnameRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> dnameRRSIGRecordList = dnameRRset.sigs();
                                int dnameRRSIGRecordListLength = dnameRRSIGRecordList.size();
                                for (int dnameRRSIGRecordIndex = 0; dnameRRSIGRecordIndex < dnameRRSIGRecordListLength; dnameRRSIGRecordIndex++) {
                                    message.addRecord(dnameRRSIGRecordList.get(dnameRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                            message.getHeader().unsetFlag(Flags.RD);
                            message.getHeader().unsetFlag(Flags.AD);
                            message.getHeader().setFlag(Flags.QR);
                            message.getHeader().setFlag(Flags.AA);
                            message.getHeader().setFlag(Flags.RD);
                            return;
                        } else {
                            if (queryResponse.isSuccessful()) {
                                List<RRset> responseRrsetList = queryResponse.answers();
                                for (RRset rRset : responseRrsetList) {
                                    List<Record> responseRecordList = rRset.rrs();
                                    Collections.shuffle(responseRecordList);
                                    int responseRecordListLength = responseRecordList.size();
                                    for (int responseRecordIndex = 0; responseRecordIndex < responseRecordListLength; responseRecordIndex++) {
                                        message.addRecord(responseRecordList.get(responseRecordIndex), Section.ANSWER);
                                    }
                                    if (dnssec) {
                                        List<RRSIGRecord> responseRRSIGRecordList = rRset.sigs();
                                        int responseRRSIGRecordListLength = responseRRSIGRecordList.size();
                                        for (int responseRRSIGRecordIndex = 0; responseRRSIGRecordIndex < responseRRSIGRecordListLength; responseRRSIGRecordIndex++) {
                                            message.addRecord(responseRRSIGRecordList.get(responseRRSIGRecordIndex), Section.ANSWER);
                                        }
                                    }
                                }
                                message.getHeader().unsetFlag(Flags.RD);
                                message.getHeader().unsetFlag(Flags.AD);
                                message.getHeader().setFlag(Flags.QR);
                                message.getHeader().setFlag(Flags.AA);
                                message.getHeader().setFlag(Flags.RD);
                                return;
                            }
                        }
                    }
                }
                Zone wildcardZone = zoneMap.get("*");
                if (wildcardZone != null) {
                    boolean dnssec = wildcardZone.dnssec && (message.getOPT() != null) && (message.getOPT().getFlags() == Type.TA);
                    if (questionType == Type.DS) {
                        System.out.println("****************");
                        System.out.println(wildcardZone);
                        RRset dsRrset = wildcardZone.findExactMatch(questionName, questionType);
                        System.out.println(dsRrset);
                        System.out.println("****************");
                        if (dsRrset != null) {
                            List<Record> dsRecordList = dsRrset.rrs();
                            int dsRecordListLength = dsRecordList.size();
                            for (int dsRecordIndex = 0; dsRecordIndex < dsRecordListLength; dsRecordIndex++) {
                                message.addRecord(dsRecordList.get(dsRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> dsRRSIGRecordList = dsRrset.sigs();
                                int dsRRSIGRecordListLength = dsRRSIGRecordList.size();
                                for (int dsRRSIGRecordIndex = 0; dsRRSIGRecordIndex < dsRRSIGRecordListLength; dsRRSIGRecordIndex++) {
                                    message.addRecord(dsRRSIGRecordList.get(dsRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                            message.getHeader().unsetFlag(Flags.RD);
                            message.getHeader().unsetFlag(Flags.AD);
                            message.getHeader().setFlag(Flags.QR);
                            message.getHeader().setFlag(Flags.AA);
                            message.getHeader().setFlag(Flags.RD);
                        } else if (geoZone != null) {
                            RRset soaRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.SOA);
                            message.addRecord(soaRRset.first(), Section.AUTHORITY);
                            if (dnssec) {
                                RRset nsecRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.NSEC);
                                message.addRecord(soaRRset.sigs().get(0), Section.AUTHORITY);
                                message.addRecord(nsecRRset.first(), Section.AUTHORITY);
                                message.addRecord(nsecRRset.sigs().get(0), Section.AUTHORITY);
                            }
                        } else {
                            RRset soaRRset = wildcardZone.findExactMatch(wildcardZone.getOrigin(), Type.SOA);
                            message.addRecord(soaRRset.first(), Section.AUTHORITY);
                            if (dnssec) {
                                RRset nsecRRset = wildcardZone.findExactMatch(wildcardZone.getOrigin(), Type.NSEC);
                                message.addRecord(soaRRset.sigs().get(0), Section.AUTHORITY);
                                message.addRecord(nsecRRset.first(), Section.AUTHORITY);
                                message.addRecord(nsecRRset.sigs().get(0), Section.AUTHORITY);
                            }
                        }
                    } else {
                        SetResponse queryResponse = wildcardZone.findRecords(message.getQuestion().getName(), message.getQuestion().getType());
                        if (queryResponse.isDelegation()) {
                            RRset nsRRset = queryResponse.getNS();
                            List<Record> nsRecordList = nsRRset.rrs();
                            int nsRecordListLength = nsRecordList.size();
                            Record nsRecord;
                            for (int nsRecordIndex = 0; nsRecordIndex < nsRecordListLength; nsRecordIndex++) {
                                nsRecord = nsRecordList.get(nsRecordIndex);
                                message.addRecord(nsRecord, Section.AUTHORITY);
                                if (nsRecord.getAdditionalName().subdomain(wildcardZone.getOrigin())) {
                                    RRset aRRset = wildcardZone.findExactMatch(nsRecord.getAdditionalName(), Type.A);
                                    RRset aaaaRRset = wildcardZone.findExactMatch(nsRecord.getAdditionalName(), Type.AAAA);
                                    if (aRRset != null) {
                                        List<Record> aRecordList = aRRset.rrs();
                                        int aRecordListLength = aRecordList.size();
                                        for (int aRecordIndex = 0; aRecordIndex < aRecordListLength; aRecordIndex++) {
                                            message.addRecord(aRecordList.get(aRecordIndex), Section.ADDITIONAL);
                                        }
                                        if (dnssec) {
                                            List<RRSIGRecord> aRRSIGRecordList = aRRset.sigs();
                                            int aRRSIGRecordListLength = aRRSIGRecordList.size();
                                            for (int aRRSIGRecordIndex = 0; aRRSIGRecordIndex < aRRSIGRecordListLength; aRRSIGRecordIndex++) {
                                                message.addRecord(aRRSIGRecordList.get(aRRSIGRecordIndex), Section.ADDITIONAL);
                                            }
                                        }
                                    }
                                    if (aaaaRRset != null) {
                                        List<Record> aaaaRecordList = aaaaRRset.rrs();
                                        int aaaaRecordListLength = aaaaRecordList.size();
                                        for (int aaaaRecordIndex = 0; aaaaRecordIndex < aaaaRecordListLength; aaaaRecordIndex++) {
                                            message.addRecord(aaaaRecordList.get(aaaaRecordIndex), Section.ADDITIONAL);
                                        }
                                        if (dnssec) {
                                            List<RRSIGRecord> aaaaRRSIGRecordList = aaaaRRset.sigs();
                                            int aaaaRRSIGRecordListLength = aaaaRRSIGRecordList.size();
                                            for (int aaaaRRSIGRecordIndex = 0; aaaaRRSIGRecordIndex < aaaaRRSIGRecordListLength; aaaaRRSIGRecordIndex++) {
                                                message.addRecord(aaaaRRSIGRecordList.get(aaaaRRSIGRecordIndex), Section.ADDITIONAL);
                                            }
                                        }
                                    }
                                }
                            }
                            if (dnssec) {
                                List<RRSIGRecord> nsRRSIGRecordList = nsRRset.sigs();
                                int nsRRSIGRecordListLength = nsRRSIGRecordList.size();
                                for (int nsRRSIGRecordIndex = 0; nsRRSIGRecordIndex < nsRRSIGRecordListLength; nsRRSIGRecordIndex++) {
                                    message.addRecord(nsRRSIGRecordList.get(nsRRSIGRecordIndex), Section.AUTHORITY);
                                }
                            }
                        } else if (queryResponse.isCNAME()) {
                            RRset cnameRRset = queryResponse.getCNAME();
                            List<Record> cnameRecordList = cnameRRset.rrs();
                            int cnameRecordListLength = cnameRecordList.size();
                            for (int cnameRecordIndex = 0; cnameRecordIndex < cnameRecordListLength; cnameRecordIndex++) {
                                message.addRecord(cnameRecordList.get(cnameRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> cnameRRSIGRecordList = cnameRRset.sigs();
                                int cnameRRSIGRecordListLength = cnameRRSIGRecordList.size();
                                for (int cnameRRSIGRecordIndex = 0; cnameRRSIGRecordIndex < cnameRRSIGRecordListLength; cnameRRSIGRecordIndex++) {
                                    message.addRecord(cnameRRSIGRecordList.get(cnameRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                        } else if (queryResponse.isDNAME()) {
                            RRset dnameRRset = queryResponse.getDNAME();
                            List<Record> dnameRecordList = dnameRRset.rrs();
                            int dnameRecordListLength = dnameRecordList.size();
                            for (int dnameRecordIndex = 0; dnameRecordIndex < dnameRecordListLength; dnameRecordIndex++) {
                                message.addRecord(dnameRecordList.get(dnameRecordIndex), Section.ANSWER);
                            }
                            if (dnssec) {
                                List<RRSIGRecord> dnameRRSIGRecordList = dnameRRset.sigs();
                                int dnameRRSIGRecordListLength = dnameRRSIGRecordList.size();
                                for (int dnameRRSIGRecordIndex = 0; dnameRRSIGRecordIndex < dnameRRSIGRecordListLength; dnameRRSIGRecordIndex++) {
                                    message.addRecord(dnameRRSIGRecordList.get(dnameRRSIGRecordIndex), Section.ANSWER);
                                }
                            }
                        } else {
                            if (queryResponse.isSuccessful()) {
                                List<RRset> responseRrsetList = queryResponse.answers();
                                for (RRset rRset : responseRrsetList) {
                                    List<Record> responseRecordList = rRset.rrs();
                                    Collections.shuffle(responseRecordList);
                                    int responseRecordListLength = responseRecordList.size();
                                    for (int responseRecordIndex = 0; responseRecordIndex < responseRecordListLength; responseRecordIndex++) {
                                        message.addRecord(responseRecordList.get(responseRecordIndex), Section.ANSWER);
                                    }
                                    if (dnssec) {
                                        List<RRSIGRecord> responseRRSIGRecordList = rRset.sigs();
                                        int responseRRSIGRecordListLength = responseRRSIGRecordList.size();
                                        for (int responseRRSIGRecordIndex = 0; responseRRSIGRecordIndex < responseRRSIGRecordListLength; responseRRSIGRecordIndex++) {
                                            message.addRecord(responseRRSIGRecordList.get(responseRRSIGRecordIndex), Section.ANSWER);
                                        }
                                    }
                                }
                            } else if (geoZone != null) {
                                RRset soaRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.SOA);
                                message.addRecord(soaRRset.first(), Section.AUTHORITY);
                                if (dnssec) {
                                    RRset nsecRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.NSEC);
                                    message.addRecord(soaRRset.sigs().get(0), Section.AUTHORITY);
                                    message.addRecord(nsecRRset.first(), Section.AUTHORITY);
                                    message.addRecord(nsecRRset.sigs().get(0), Section.AUTHORITY);
                                }
                            } else {
                                RRset soaRRset = wildcardZone.findExactMatch(wildcardZone.getOrigin(), Type.SOA);
                                message.addRecord(soaRRset.first(), Section.AUTHORITY);
                                if (dnssec) {
                                    RRset nsecRRset = wildcardZone.findExactMatch(wildcardZone.getOrigin(), Type.NSEC);
                                    message.addRecord(soaRRset.sigs().get(0), Section.AUTHORITY);
                                    message.addRecord(nsecRRset.first(), Section.AUTHORITY);
                                    message.addRecord(nsecRRset.sigs().get(0), Section.AUTHORITY);
                                }
                            }

                        }
                        message.getHeader().unsetFlag(Flags.RD);
                        message.getHeader().unsetFlag(Flags.AD);
                        message.getHeader().setFlag(Flags.QR);
                        message.getHeader().setFlag(Flags.AA);
                        message.getHeader().setFlag(Flags.RD);
                    }
                } else if (geoZone != null) {
                    boolean dnssec = geoZone.dnssec && (message.getOPT() != null) && (message.getOPT().getFlags() == Type.TA);
                    RRset soaRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.SOA);
                    message.addRecord(soaRRset.first(), Section.AUTHORITY);
                    if (dnssec) {
                        RRset nsecRRset = geoZone.findExactMatch(geoZone.getOrigin(), Type.NSEC);
                        message.addRecord(soaRRset.sigs().get(0), Section.AUTHORITY);
                        message.addRecord(nsecRRset.first(), Section.AUTHORITY);
                        message.addRecord(nsecRRset.sigs().get(0), Section.AUTHORITY);
                    }
                    message.getHeader().unsetFlag(Flags.RD);
                    message.getHeader().unsetFlag(Flags.AD);
                    message.getHeader().setFlag(Flags.QR);
                    message.getHeader().setFlag(Flags.AA);
                    message.getHeader().setFlag(Flags.RD);
                }
            }
        } catch (Exception ignored) {
        }
    }
}
