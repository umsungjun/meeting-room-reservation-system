package com.jang.mtg.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;


import com.jang.mtg.model.MrResTimeVO;
import com.jang.mtg.model.MrReserveVO;
import com.jang.mtg.model.MtRoomVO;
import com.jang.mtg.model.SearchVO;



@Mapper
public interface MtRoomMapper {

List<MtRoomVO> getMtRoomList(SearchVO searchVO); //��ϵ� ȸ�ǽ� ��ü �б�
	
	List<MtRoomVO> Search_getMtRoomList(String searchKeyword); //��ϵ� ȸ�ǽ� ��ü �б�
	
	MtRoomVO getMtRoom(int mrNo); //Ư��ȸ�� �б�
	
	int insertMtRoom(MtRoomVO mtRoomVO); //ȸ�ǽ� ���
	
	int updateMtRoom(MtRoomVO mtRoomVO); // ȸ�ǽ� ��������
	
	int deleteMtRoom(int mrNo); //ȸ�ǽ� ������
	
	List<MrReserveVO> getMrReserveList(MrResTimeVO mrResTimeVO1);// �Ϻ�ȸ�ǽǺ� ������ �б�
	
	MrReserveVO getMrReserve(int reNo); //Ư�� ���� �б�
	
	int insertMrReserve(MrReserveVO mrReserveVO);//���� ���
	
	int updateMrReserve(MrReserveVO mrReserveVO); //���� ����
	
	int deleteMrReserve(int reNo); //�������
	
	int resDupCeck(MrReserveVO mrReserveVO);//���� �ߺ�üũ
	
	MrReserveVO getMrReserveByTime(MrReserveVO mrReserveVO); //Ư���ð� ���� �б�
	
	StringBuffer getPageUrl(SearchVO searchVO);
	
	int getTotalRow(SearchVO searchVO);// ��ü�� �� ��ȸ
	
	int getTotalRow2(SearchVO searchVO);// ��ü�� �� ��ȸ
	
	List<MtRoomVO> getMtRoomList(@Param(value = "startRow") int startRow, @Param(value = "endRow") int endRow);
}
