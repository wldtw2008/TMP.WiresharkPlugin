--�o�OWireshark �x�W�����TMP�q��ѪRPlugin(LUA�{���X)
--�@�̡G wldtw2008@gmail.com 2022-11-2
--�ϥΤ�k�G
--1. �s��TMP.lua�A�Ԩ�̤U���A�K�[�{���X tcp_encap_table:add(PVC�q�T��,protoTMP)
--2. ���}Wireshark�A�I��u��CHelp->About->Folders->GlobalPlugins(�����i�H���}��Ƨ�)�A��o��TMP.lua���o�Ӹ�Ƨ�
--3. ����Wireshark�Y�i

do    
    local protoTMP = Proto.new("TMP", "Taifex Message Protocol")
    --�ŧi�q
	local f_HdrMsgType = ProtoField.uint32("TMP.Type","Type",base.HEX,
	{[10]="L10", [20]="L20", [30]="L30",[40]="L40",[41]="L41",[50]="L50",[60]="L60",[101]="R01",[102]="R02",[103]="R03",[104]="R04",[105]="R05",[114]="R14",[122]="R22"
	})
	local f_HdrMsgLen = ProtoField.uint16("MsgLen","MsgLen",base.DEC)
	local f_HdrSeqNum = ProtoField.uint32("SeqNum","SeqNum",base.DEC)
	local f_TmpTimeEpoch = ProtoField.uint32("TS","TmpTime.Epoch",base.DEC) --�ɶ��W ��Ƴ���
	local f_TmpTimeMs= ProtoField.uint16("TS","TmpTime.Ms",base.DEC)        --�ɶ��W �@����
	local f_FcmId = ProtoField.uint16("FcmId","FcmId",base.DEC)--���f�ӽs��
	local f_SessionId = ProtoField.uint16("SessionId","SessionId",base.DEC)--PVC Session ID
	
	local f_HeaderArea = ProtoField.bytes("Header")
	local f_BodyArea = ProtoField.bytes("Body")
	local f_ChkSumyByte = ProtoField.uint8("ChkSum", "ChkSum",base.HEX)
	
	local f_ExecType = ProtoField.uint8("ExecType","ExecType",base.HEX,
	{[string.byte('0')]="New", [string.byte('4')]="Cancel", [string.byte('5')]="DecressQty", [string.byte('M')]="ModifyPrc", [string.byte('m')]="ModifyPrc", [string.byte('I')]="Query"
	})
	
	local f_cmid = ProtoField.uint16("CmId","CmId",base.DEC)--����|���s
	local f_OrderNo = ProtoField.string("OrderNo","OrderNo")--�e�U�Ѹ�
	local f_OrdId = ProtoField.uint32("OrdId","OrdId",base.DEC)-- �e�U�Ѭy����	��e�U��y����(�̦h 7 �X�Ʀr)
	local f_UserDefine = ProtoField.bytes("UserDefine")--���f�Ӧۭq�ܼ� ����t�Φb�s�W�R���q����ɡA�|�۰ʧ�s���Ȩ�e�U�檬�A
	local f_SymbolType = ProtoField.uint8("SymbolType","SymbolType",base.DEC)--�ӫ~�N���榡 R01(1: num, 2 : text)	R31(3: num, 4 : text)
	local f_SymbolID = ProtoField.string("SymbolID","SymbolID")--�ӫ~�N������	x �����i�� num	�� text ���N
	local f_Price = ProtoField.uint32("Price","Price",base.DEC)--�e�U���� �Ѧ� �e�U����
	local f_Qty = ProtoField.uint32("Qty","Qty",base.DEC)--�e�U�f��
	local f_InvestorAcno = ProtoField.uint32("InvestorAcno","InvestorAcno",base.DEC)--����H�b��
	local f_InvestorFlag=ProtoField.string("InvestorFlag","InvestorFlag")--���H�����X  1�@�� 2���� 8�y��
	local f_Side = ProtoField.uint8("Side","Side",base.DEC, {[1]="Buy",[2]="Sell"})--�R��O 1:�R, 2 : �� 
	local f_OrdType = ProtoField.uint8("OrdType","OrdType",base.DEC, {[1]="Market",[2]="Limit",[3]="LimitMarket"})--�e�U�覡 1 : Market, 2 : Limit, 3 :�@�w�d�򥫻��e�U
	local f_TimeInForce = ProtoField.uint8("TimeInForce","TimeInForce",base.DEC, {[4]="FOK",[3]="IOC",[0]="ROD",[8]="Quote"})--�e�U���� FOK:4, IOC:3, ROD:0, �����@�w������t�Φ۰ʧR��:8
	local f_PositionEffect=ProtoField.string("PositionEffec","PositionEffec")--�}���ܽX open : O(�^��j�g),	close : C, daytrade : D	����v�s�ܧt���w	����R�P : A(Options Only)	�N���R�P : 7
	local f_OrderSource=ProtoField.string("OrderSource","OrderSource")--char �e�U���O���O	D : �M�u�U��(�tVPN�B�ʳ����M�ݺ���) A : API�U�� M : ��ʸ���U�� W : �����U��	P : �ӤH�q���n��U�� V : �y���U��	G : �@��e�U�U��(�ѭ��B�q�ܡB�q�����覡)
	local f_InfoSource=ProtoField.string("InfoSource","InfoSource")--�污��T�ӷ����O	1.�Ѧ污��T�t�Ӵ��Ѫ̡A��J�Ӧ污��T�t�ӥN�X(�Ԧ污��T�t�ӥN�X���)�C 2.�Ѵ��f�Ӧۦ洣�Ѧ污��T�̡A��J��999��
	local f_StatusCode = ProtoField.uint8("StatusCod","StatusCod",base.DEC, {[0]="OK"})--���A�T���X���`�� 0
	local f_LeavesQty = ProtoField.uint32("LeavesQty","LeavesQty",base.DEC)--�{�Ѿl�q
	local f_BeforeQty = ProtoField.uint32("BeforeQty","BeforeQty",base.DEC)--���X�e�Ѿl�e�U�q
	local f_Leg1Prc = ProtoField.uint32("Leg1Prc","Leg1Prc",base.DEC)--����ӫ~�������
	local f_Leg1Qty = ProtoField.uint32("Leg1Qty","Leg1Qty",base.DEC)--����ӫ~����f��
	local f_Leg2Prc = ProtoField.uint32("Leg2Prc","Leg2Prc",base.DEC)--����ӫ~�������
	local f_Leg2Qty = ProtoField.uint32("Leg2Qty","Leg2Qty",base.DEC)--����ӫ~����f��
	local f_UniqId = ProtoField.uint32("UniqId","UniqId",base.DEC)--�ߤ@�Ǹ�	target_id = 4 �h���t�ΰߤ@�Ǹ�	(OrderID);target_id = 8, 9 �h���^���Ǹ�(cm_sub_seq)
	local f_RptSeq = ProtoField.uint32("RptSeq","RptSeq",base.DEC)--�^���Ǹ�target_id = 4 �ɬ�session �y����(session_seq)  target_id = 8�B9 �ɬ�����|���^���Ǹ�(cm_seq)
	local f_ProtocolType = ProtoField.uint32("ProtocolType","ProtocolType",base.DEC, {[0]="Reserved",[1]="TMP",[2]="FIX"})--�s���ƨӷ�0�G�O�d 1�GTMP 2�GFIX, 
	
    protoTMP.fields = {f_HdrMsgLen,f_HdrSeqNum,f_TmpTimeEpoch, f_TmpTimeMs, 
	f_HdrMsgType,  f_FcmId, f_SessionId,
	f_HeaderArea,  f_BodyArea, f_ChkSumyByte,
	f_ExecType,f_cmid,f_OrderNo	,f_OrdId,f_UserDefine,f_SymbolType,f_SymbolID,f_Price,f_Qty,f_InvestorAcno,f_InvestorFlag,f_Side,f_OrdType,f_TimeInForce,f_PositionEffect,f_OrderSource,f_InfoSource,
	f_StatusCode,f_LeavesQty,f_BeforeQty,f_Leg1Prc,f_Leg1Qty,f_Leg2Prc,f_Leg2Qty,f_UniqId,f_RptSeq,f_ProtocolType}

    --�u���ѪR������
    local function check_and_dissector_TMP(buf,pkt,root)		
        local buf_len = buf:len();
        --�ʥ]���פӵu�N���OTMP
        if buf_len < 17 then return false end
		
		pkt.cols['protocol'] = "$$TMP"
		
		local msglen = buf(pkt.desegment_offset + 0,2):uint()
		local msgtype = buf(pkt.desegment_offset + 12,1):uint()
		local strMsgtype = "??("..msgtype..")"		
		
		--�W�LMTU�Q���Ϊ�TCP�ʥ] �ΤU���o�Өְ_��
		if pkt.desegment_offset + msglen+3 > buf:len() then
			pkt.desegment_len = pkt.desegment_offset + msglen+3 - buf:len()
			return true
		end

		local t = root:add(protoTMP,buf)

		--Header
		local hdr = t:add(f_HeaderArea, buf(pkt.desegment_offset + 0, 17))
		hdr:add(f_HdrMsgLen, buf(pkt.desegment_offset + 0,2))
		hdr:add(f_HdrSeqNum, buf(pkt.desegment_offset + 2,4))
		hdr:add(f_TmpTimeEpoch, buf(pkt.desegment_offset + 6,4))
		hdr:add(f_TmpTimeMs, buf(pkt.desegment_offset + 10,2))
		hdr:add(f_HdrMsgType, buf(pkt.desegment_offset + 12,1))
		hdr:add(f_FcmId, buf(pkt.desegment_offset + 13, 2))
		hdr:add(f_SessionId, buf(pkt.desegment_offset + 15,2))

		--Body
		local bodyBegIdx = pkt.desegment_offset + 17
		local body = t:add(f_BodyArea, buf(bodyBegIdx, msglen+2-17))
		if (msgtype==10) then
			strMsgtype = "L10"
		elseif (msgtype==20) then
			strMsgtype = "L20"
		elseif (msgtype==30) then
			strMsgtype = "L30"
		elseif (msgtype==40) then
			strMsgtype = "L40"
		elseif (msgtype==41) then
			strMsgtype = "L41"
		elseif (msgtype==50) then
			strMsgtype = "L50"
		elseif (msgtype==60) then
			strMsgtype = "L60"
		elseif (msgtype==101) then					
			strMsgtype = "R01(??)"
			local execType = buf(bodyBegIdx+0,1):string()
			if (execType=="0") then
				strMsgtype = "R01(New)"
			elseif (execType=="4") then
				strMsgtype = "R01(Cancel)"
			elseif (execType=="5") then
				strMsgtype = "R01(DecressQty)"
			elseif (execType=="M") then
				strMsgtype = "R01(ModifyPrc:M)"
			elseif (execType=="m") then
				strMsgtype = "R01(ModifyPrc:m)"
			elseif (execType=="I") then
				strMsgtype = "R01(Query)"
			end
			body:add(f_ExecType, buf(bodyBegIdx+0,1))
			body:add(f_cmid, buf(bodyBegIdx+1,2))
			body:add(f_FcmId, buf(bodyBegIdx+3,2))
			body:add(f_OrderNo, buf(bodyBegIdx+5,5))
			body:add(f_OrdId, buf(bodyBegIdx+10,4))
			body:add(f_UserDefine, buf(bodyBegIdx+14,8))
			body:add(f_SymbolType, buf(bodyBegIdx+22,1))
			body:add(f_SymbolID, buf(bodyBegIdx+23,20))
			body:add(f_Price, buf(bodyBegIdx+43,4))
			body:add(f_Qty, buf(bodyBegIdx+47,2))
			body:add(f_InvestorAcno, buf(bodyBegIdx+49,4))
			body:add(f_InvestorFlag, buf(bodyBegIdx+53,1))
			body:add(f_Side, buf(bodyBegIdx+54,1))
			body:add(f_OrdType, buf(bodyBegIdx+55,1))
			body:add(f_TimeInForce, buf(bodyBegIdx+56,1))
			body:add(f_PositionEffect, buf(bodyBegIdx+57,1))
			body:add(f_OrderSource, buf(bodyBegIdx+58,1))
			body:add(f_InfoSource, buf(bodyBegIdx+59,3))
		elseif (msgtype==102) then
			strMsgtype = "R02(Reply Long)"
		elseif (msgtype==103) then
			strMsgtype = "R03(Error Order)"
			body:add(f_StatusCode, buf(bodyBegIdx+0,1))
			body:add(f_ExecType, buf(bodyBegIdx+1,1))
			body:add(f_FcmId, buf(bodyBegIdx+2,2))
			body:add(f_OrderNo, buf(bodyBegIdx+4,5))
			body:add(f_OrdId, buf(bodyBegIdx+9,4))
			body:add(f_UserDefine, buf(bodyBegIdx+13,8))
			body:add(f_RptSeq, buf(bodyBegIdx+21,4))
			body:add(f_Side, buf(bodyBegIdx+25,1))
		elseif (msgtype==104) then
			strMsgtype = "R04"
		elseif (msgtype==105) then
			strMsgtype = "R05"
		elseif (msgtype==114) then
			strMsgtype = "R14"
		elseif (msgtype==122) then
			strMsgtype = "R22(Reply Short)"
			body:add(f_StatusCode, buf(bodyBegIdx+0,1))
			body:add(f_ExecType, buf(bodyBegIdx+1,1))
			body:add(f_FcmId, buf(bodyBegIdx+2,2))
			body:add(f_OrderNo, buf(bodyBegIdx+4,5))
			body:add(f_OrdId, buf(bodyBegIdx+9,4))
			body:add(f_UserDefine, buf(bodyBegIdx+13,8))

			body:add(f_Side, buf(bodyBegIdx+21,1))
			body:add(f_PositionEffect, buf(bodyBegIdx+22,1))

			body:add(f_LeavesQty, buf(bodyBegIdx+23,2))
			body:add(f_BeforeQty, buf(bodyBegIdx+25,2))
			body:add(f_Leg1Prc, buf(bodyBegIdx+27,4))
			body:add(f_Leg2Prc, buf(bodyBegIdx+31,4))
			body:add(f_Leg1Qty, buf(bodyBegIdx+35,2))
			body:add(f_Leg2Qty, buf(bodyBegIdx+37,2))
			body:add(f_TmpTimeEpoch, buf(bodyBegIdx+39,4))
			body:add(f_TmpTimeMs, buf(bodyBegIdx+43,2))

			body:add(f_UniqId, buf(bodyBegIdx+45,4))
			body:add(f_RptSeq, buf(bodyBegIdx+49,4))
			body:add(f_ProtocolType, buf(bodyBegIdx+53,1))
			body:add(f_Price, buf(bodyBegIdx+54,4))
		end

		--CheckSum
		t:add(f_ChkSumyByte, buf(pkt.desegment_offset+msglen+2, 1))
		--�U���o��[�`��CheckSum
		local sum = 0;		
		for i = pkt.desegment_offset,pkt.desegment_offset+msglen+2-1, 1 --for init,max/min value, increment
		do
			sum = (sum + (buf(i, 1):uint()))
		end
		local strCheck=string.format("   Sum = 0x%08x",sum)
		t:add(strCheck)
		
		if (pkt.desegment_offset == 0) then
			pkt.cols['info'] = "TMP"
		end
		pkt.cols['info']:append(" "..strMsgtype)
		
		--�p�G�W�L�@�ӥ] ���N�~�򻼰j�U�h�ѪR
		if buf_len > pkt.desegment_offset + msglen+3 then
			pkt.desegment_offset = pkt.desegment_offset + msglen+3
			check_and_dissector_TMP(buf,pkt,root)
		end
			
        return true
    end
	
    function protoTMP.dissector(buf,pkt,root)
		local data_dis = Dissector.get("data")
        if check_and_dissector_TMP(buf,pkt,root) then
            --�ѪR���\
        else
            --�ѪR���ѡA�N���OTMP, �n���W�h��
            data_dis:call(buf,pkt,root)
        end
    end
    
    local tcp_encap_table = DissectorTable.get("tcp.port")
    --�ݭn�ѪR��PORT���b�o�̲K�[
    tcp_encap_table:add(30210,protoTMP)
	tcp_encap_table:add(20244,protoTMP)
    tcp_encap_table:add(30205,protoTMP)
	tcp_encap_table:add(30001,protoTMP)
	tcp_encap_table:add(30002,protoTMP)
end