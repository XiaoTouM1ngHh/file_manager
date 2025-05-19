#include "FileManagerAPI.hpp"

int main() {
	FileManagerAPI* FileManager = new FileManagerAPI();
	std::vector<CategoryInfo> Categories =  FileManager->GetCategories();
	CProgressCtrl* m_progress = (CProgressCtrl*)par;
	m_progress->SetRange(0, FileManager->GetTotalFiles());
	
	for (size_t i = 0; i < Categories.size(); i++)
	{
		CategoryInfo Category = Categories.at(i);
		std::wstring CategoryName = utf8_to_wstring(Category.name);
		int CategoryID = Category.id;
		//创建文件夹
		std::wstring FilePath = L"./Script/"+CategoryName;
		if (!std::filesystem::exists(FilePath))
		{
			std::filesystem::create_directory(FilePath);
		}
		//获取文件列表
		std::vector<FileInfo> Files = FileManager->GetFilesByCategory(CategoryID);
		for (size_t j = 0; j < Files.size(); j++)
		{
			FileInfo File = Files.at(j);
			std::wstring FileName = utf8_to_wstring(File.filename);
			if (File.is_encrypted)
			{
				FileName = FileName + L"." + utf8_to_wstring(File.extension) + L"x";
			}
			else {

				FileName = FileName + L"." + utf8_to_wstring(File.extension);

			}
			std::wstring SavePath = FilePath+L"/"+FileName;
			//判断文件是否存在
			if (!std::filesystem::exists(SavePath))
			{
				//下载文件
				FileManager->DownloadFile(File.guid, SavePath);
			}else{
				//比较文件MD5
				bool isSame = FileManager->CompareFileMD5(File, SavePath);
				if (!isSame)
				{
					//下载文件
					FileManager->DownloadFile(File.guid, SavePath);
				}
			}

			m_progress->SetPos(m_progress->GetPos()+1);
		}
		
	}
	MessageBox(NULL,"下载完成", "提示",MB_OK);
	delete FileManager;
    return 0;
} 